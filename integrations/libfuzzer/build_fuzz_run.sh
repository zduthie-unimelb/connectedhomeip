#!/usr/bin/env bash

# (Optional) builds linux unit tests to out/clang (with no coverage)
# And runs specific fuzzing binary

set -e

SUPPORTED_DRIVERS=(cert_chip cert_der minmdns qr tlv)
build_matter=false

CHIP_ROOT="/home/ubuntu/connectedhomeip"
OUTPUT_ROOT="$CHIP_ROOT/out/clang"
FUZZ_DATE="$(date '+%Y%m%d_%H%M%S')"

DRIVER="tlv"
SEEDS="$CHIP_ROOT/seeds"
MINUTES=2
DICT_ARG=""
MAXLEN_ARG="" # Hard-coded
# MAXLEN_ARG="-max_len=10240" # Hard-coded

help() {

    echo "Usage: [--build] [--driver=<cert_chip|cert_der|minmdns|qr|tlv>] [--seeds=<seeds_dir>] [--dict=<dict_file>] [--minutes=<minutes>] "
    echo
    echo "Misc:
  -h, --help                Print this help, then exit."
    echo
    echo "Options:
  -b, --build               Whether to re-build the matter project.
  -d, --driver              Specify the fuzz driver. One of cert, minmdns, qr or tlv.
                            Defaults to 'tlv'.
  -s, --seeds               Specify the fuzzing seed directory.
                            Defaults to ./seeds
  -i, --dict                Specify the fuzzing dictionary.
                            Defaults to (none)
  -m, --minutes             Specify how long to run fuzzing.
                            Defaults to 2 minutes.
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
        -m=* | --minutes=*)
            MINUTES="${i#*=}"
            shift
            ;;
        -s=* | --seeds=*)
            SEEDS="${i#*=}"
            shift
            ;;
        -i=* | --dict=*)
            DICT_ARG="-dict=${i#*=}"
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

CORPUS="$CHIP_ROOT/corpus_${DRIVER}_$FUZZ_DATE"

COVERAGE_NAME="coverage_${DRIVER}_$FUZZ_DATE"
COVERAGE_ROOT="$OUTPUT_ROOT/$COVERAGE_NAME"

# Create directories if required
mkdir -p $CORPUS

# Delete all previous 
find $OUTPUT_ROOT -name "*.gcda" -type f -delete

# Build fuzzing binaries (with no coverage - faster!)
if [ "$build_matter" == true ]; then
    BUILD_TYPE="clang"
    ./scripts/build/gn_gen.sh --args="is_clang=true"
    ./scripts/run_in_build_env.sh "ninja -C out/$BUILD_TYPE"
fi

# Run the fuzzing binary to generate the corpus (with symbolizer)
echo "Starting Fuzzing at $FUZZ_DATE"
set +e
ASAN_OPTIONS=external_symbolizer_path=/home/ubuntu/connectedhomeip/.environment/cipd/packages/pigweed/bin/llvm-symbolizer timeout $(( $MINUTES*60 )) $FUZZ_BINARY_PATH $CORPUS $SEEDS $DICT_ARG $MAXLEN_ARG 1> /dev/null
set -e
echo "Corpus saved to $CORPUS"
echo "Starting Fuzzing at $FUZZ_DATE"
echo "Finished Fuzzing at $(date '+%Y%m%d_%H%M%S')"
