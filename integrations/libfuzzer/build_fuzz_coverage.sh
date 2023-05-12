#!/usr/bin/env bash

# (Optional) builds linux unit tests to out/clang (with coverage)
# And feeds a corpus into a fuzzing binary and collects coverage

set -e

SUPPORTED_DRIVERS=(cert_chip cert_der minmdns qr tlv)
build_matter=false

CHIP_ROOT="/home/ubuntu/connectedhomeip"
OUTPUT_ROOT="$CHIP_ROOT/out/clang"

help() {

    echo "Usage: --driver=<cert_chip|cert_der|minmdns|qr|tlv> --corpus=<corpus_dir> [--build]"
    echo
    echo "Misc:
  -h, --help                Print this help, then exit."
    echo
    echo "Options:
  -b, --build               Whether to re-build the matter project.
  -d, --driver              Specify the fuzz driver. One of cert, minmdns, qr or tlv.
  -c, --corpus              Specify the fuzzing corpus directory.
  "
}

for i in "$@"; do
    case $i in
        -h | --help)
            help
            exit 1
            ;;
        -b | --build)
            build_matter=true
            shift
            ;;
        -d=* | --driver=*)
            DRIVER="${i#*=}"
            shift
            ;;
        -c=* | --corpus=*)
            CORPUS="${i#*=}"
            shift
            ;;
        *)
            echo "Unknown Option \"$1\""
            echo
            help
            exit 1
            ;;
    esac
done

FUZZ_BINARY_NAME="fuzz-tlv-reader"
case $DRIVER in
    "cert_chip")
        FUZZ_BINARY_NAME="fuzz-chip-cert"
        ;;
    "cert_der")
        FUZZ_BINARY_NAME="fuzz-der-cert"
        ;;
    "minmdns")
        FUZZ_BINARY_NAME="fuzz-minmdns-packet-parsing"
        ;;
    "qr")
        FUZZ_BINARY_NAME="fuzz-qrcode-setup-payload-parsing"
        ;;
    "tlv")
        FUZZ_BINARY_NAME="fuzz-tlv-reader"
        ;;
    *)
        echo "ERROR: Driver $DRIVER not supported"
        help
        exit 1
esac

FUZZ_BINARY_PATH="$OUTPUT_ROOT/tests/$FUZZ_BINARY_NAME"

CORPUS_NAME=$(basename $CORPUS)
COVERAGE_NAME="coverage_$CORPUS_NAME"
COVERAGE_ROOT="$OUTPUT_ROOT/$COVERAGE_NAME"

# Delete all previous 
find $OUTPUT_ROOT -name "*.gcda" -type f -delete

# Build fuzzing binaries (with coverage)
if [ "$build_matter" == true ]; then
    BUILD_TYPE="clang"
    ./scripts/build/gn_gen.sh --args="is_clang=true use_coverage=true"
    ./scripts/run_in_build_env.sh "ninja -C out/$BUILD_TYPE"
fi

# Run the corpus through the coverage enabled fuzzing binary (with symbolizer)
ASAN_OPTIONS=external_symbolizer_path=/home/ubuntu/connectedhomeip/.environment/cipd/packages/pigweed/bin/llvm-symbolizer $FUZZ_BINARY_PATH $CORPUS -runs=0 1> /dev/null

# Remove misc support components from coverage statistics
rm -rf "$OUTPUT_ROOT/obj/src/app/app-platform"
rm -rf "$OUTPUT_ROOT/obj/src/app/common"
rm -rf "$OUTPUT_ROOT/obj/src/app/util/mock"
rm -rf "$OUTPUT_ROOT/obj/src/controller/python"
rm -rf "$OUTPUT_ROOT/obj/src/lib/dnssd/platform"
rm -rf "$OUTPUT_ROOT/obj/src/lib/shell"
rm -rf "$OUTPUT_ROOT/obj/src/lwip"
rm -rf "$OUTPUT_ROOT/obj/src/platform"
rm -rf "$OUTPUT_ROOT/obj/src/tools"

# Remove unit test itself from coverage statistics
find "$OUTPUT_ROOT/obj/src/" -depth -name 'tests' -exec rm -rf {} \;

rm -rf "$OUTPUT_ROOT/obj/src/app/clusters"

# Create and collect coverage
set -x
mkdir -p "$COVERAGE_ROOT"
lcov --gcov-tool $CHIP_ROOT/cov_clang.sh --initial --capture --directory "$OUTPUT_ROOT/obj/src" --exclude="$PWD"/zzz_generated/* --exclude="$PWD"/third_party/* --exclude=/usr/include/* --output-file "$COVERAGE_ROOT/lcov_base.info" 1> /dev/null
lcov --gcov-tool $CHIP_ROOT/cov_clang.sh --capture --directory "$OUTPUT_ROOT/obj/src" --exclude="$PWD"/zzz_generated/* --exclude="$PWD"/third_party/* --exclude=/usr/include/* --output-file "$COVERAGE_ROOT/lcov_test.info" 1> /dev/null
lcov --gcov-tool $CHIP_ROOT/cov_clang.sh --add-tracefile "$COVERAGE_ROOT/lcov_base.info" --add-tracefile "$COVERAGE_ROOT/lcov_test.info" --output-file "$COVERAGE_ROOT/lcov_final.info"
genhtml "$COVERAGE_ROOT/lcov_final.info" --output-directory "$COVERAGE_ROOT/html" 1> /dev/null

# Zip for easy reference / transfer
zip -9 -y -r -q "$CHIP_ROOT/$COVERAGE_NAME.zip" $COVERAGE_ROOT
