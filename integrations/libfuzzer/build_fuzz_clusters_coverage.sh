#!/usr/bin/env bash

# Builds linux all-clusters-app to out/linux-x64-all-clusters-no-ble-asan-libfuzzer-coverage-clang
# And collects coverage information. Saves to coverage_clusters.zip

set -e

FUZZ_DATE="$(date '+%Y%m%d_%H%M%S')"
CLUSTERS_DATE="clusters_$FUZZ_DATE"
CHIP_ROOT="/home/ubuntu/connectedhomeip"
COVERAGE_NAME="coverage_$CLUSTERS_DATE"
OUTPUT_ROOT="$CHIP_ROOT/out/linux-x64-all-clusters-no-ble-asan-libfuzzer-coverage-clang"
COVERAGE_ROOT="$OUTPUT_ROOT/$COVERAGE_NAME"

CORPUS="$CHIP_ROOT/corpus_$CLUSTERS_DATE"
SEEDS="$CHIP_ROOT/seeds_clusters"
MINUTES=5
DICT_ARG=""
MAXLEN_ARG="" # Hard-coded
# MAXLEN_ARG="-max_len=10240" # Hard-coded

help() {

    echo "Usage: [--corpus=<corpus_dir>] [--seeds=<seeds_dir>] [--dict=<dict_file>] [--minutes=<minutes>]"
    echo
    echo "Misc:
  -h, --help                Print this help, then exit."
    echo
    echo "Options:
  -c, --corpus              Specify the fuzzing corpus directory.
                            Defaults to corpus_clusters_yyyymmmdd_HHMMSS
  -s, --seeds               Specify the fuzzing seed directory.
                            Defaults to seeds_clusters
  -i, --dict                Specify the fuzzing dictionary.
                            Defaults to (none)
  -m, --minutes             Specify how long to run fuzzing.
                            Defaults to 5 minutes.
  "
}

for i in "$@"; do
    case $i in
        -h | --help)
            help
            exit 1
            ;;
        -c=* | --corpus=*)
            CORPUS="${i#*=}"
            shift
            ;;
        -m=* | --minutes=*)
            MINUTES="${i#*=}"
            shift
            ;;
        -i=* | --dict=*)
            DICT_ARG="-dict=${i#*=}"
            shift
            ;;
        -s=* | --seeds=*)
            SEEDS="${i#*=}"
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

# Create directories if required
mkdir -p $CORPUS

# Build fuzzing binary
./scripts/run_in_build_env.sh "./scripts/build/build_examples.py --target linux-x64-all-clusters-no-ble-asan-libfuzzer-coverage-clang build"

# Delete all previous 
find $OUTPUT_ROOT -name "*.gcda" -type f -delete

# Run the fuzzing binary (with symbolizer)
echo "Starting Fuzzing at $FUZZ_DATE"
set +e
sudo ASAN_OPTIONS=external_symbolizer_path=/home/ubuntu/connectedhomeip/.environment/cipd/packages/pigweed/bin/llvm-symbolizer FUZZ_CAMPAIGN_MINUTES=$MINUTES ./out/linux-x64-all-clusters-no-ble-asan-libfuzzer-coverage-clang/chip-all-clusters-app-fuzzing $CORPUS $SEEDS $DICT_ARG $MAXLEN_ARG 1> /dev/null
set -e
echo "Corpus saved to $CORPUS"
echo "Started Fuzzing at $FUZZ_DATE"
echo "Finished Fuzzing at $(date '+%Y%m%d_%H%M%S')"

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
find "$OUTPUT_ROOT/obj/third_party/connectedhomeip/src/" -depth -name 'tests' -exec rm -rf {} \;

# Create and collect coverage
set -x
mkdir -p "$COVERAGE_ROOT"
lcov --gcov-tool $CHIP_ROOT/cov_clang.sh --initial --capture --directory "$OUTPUT_ROOT/obj/third_party/connectedhomeip/src" --exclude="$OUTPUT_ROOT/obj/third_party/connectedhomeip"/zzz_generated/* --exclude="$OUTPUT_ROOT/obj/third_party/connectedhomeip"/third_party/* --exclude=/usr/include/* --output-file "$COVERAGE_ROOT/lcov_base.info" 1> /dev/null
lcov --gcov-tool $CHIP_ROOT/cov_clang.sh --capture --directory "$OUTPUT_ROOT/obj/third_party/connectedhomeip/src" --exclude="$OUTPUT_ROOT/obj/third_party/connectedhomeip"/zzz_generated/* --exclude="$OUTPUT_ROOT/obj/third_party/connectedhomeip"/third_party/* --exclude=/usr/include/* --output-file "$COVERAGE_ROOT/lcov_test.info" 1> /dev/null
lcov --gcov-tool $CHIP_ROOT/cov_clang.sh --add-tracefile "$COVERAGE_ROOT/lcov_base.info" --add-tracefile "$COVERAGE_ROOT/lcov_test.info" --output-file "$COVERAGE_ROOT/lcov_final.info"
genhtml "$COVERAGE_ROOT/lcov_final.info" --output-directory "$COVERAGE_ROOT/html" 1> /dev/null

# Zip for easy reference / transfer
zip -9 -y -r -q "$CHIP_ROOT/$COVERAGE_NAME.zip" $COVERAGE_ROOT
