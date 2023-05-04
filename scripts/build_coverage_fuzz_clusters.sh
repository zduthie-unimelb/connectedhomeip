#!/usr/bin/env bash

./scripts/run_in_build_env.sh "./scripts/build/build_examples.py --target linux-x64-all-clusters-no-ble-asan-libfuzzer-coverage-clang build"

CHIP_ROOT="/home/ubuntu/connectedhomeip"
COVERAGE_NAME="coverage_clusters_raw"
OUTPUT_ROOT="$CHIP_ROOT/out/linux-x64-all-clusters-no-ble-asan-libfuzzer-coverage-clang"
COVERAGE_ROOT="$OUTPUT_ROOT/$COVERAGE_NAME"

find $OUTPUT_ROOT -name "*.gcda" -type f -delete

ASAN_OPTIONS=external_symbolizer_path=/home/ubuntu/connectedhomeip/.environment/cipd/packages/pigweed/bin/llvm-symbolizer FUZZ_CAMPAIGN_MINUTES=30 ./out/linux-x64-all-clusters-no-ble-asan-libfuzzer-coverage-clang/chip-all-clusters-app-fuzzing CORPUS_clusters_raw SEEDS_handshake 1> /dev/null

rm -rf "$OUTPUT_ROOT/obj/src/app/app-platform"
rm -rf "$OUTPUT_ROOT/obj/src/app/common"
rm -rf "$OUTPUT_ROOT/obj/src/app/util/mock"
rm -rf "$OUTPUT_ROOT/obj/src/controller/python"
rm -rf "$OUTPUT_ROOT/obj/src/lib/dnssd/platform"
rm -rf "$OUTPUT_ROOT/obj/src/lib/shell"
rm -rf "$OUTPUT_ROOT/obj/src/lwip"
rm -rf "$OUTPUT_ROOT/obj/src/platform"
rm -rf "$OUTPUT_ROOT/obj/src/tools"

find "$OUTPUT_ROOT/obj/third_party/connectedhomeip/src/" -depth -name 'tests' -exec rm -rf {} \;
mkdir -p "$COVERAGE_ROOT"
lcov --gcov-tool $CHIP_ROOT/cov_clang.sh --initial --capture --directory "$OUTPUT_ROOT/obj/third_party/connectedhomeip/src" --exclude="$OUTPUT_ROOT/obj/third_party/connectedhomeip"/zzz_generated/* --exclude="$OUTPUT_ROOT/obj/third_party/connectedhomeip"/third_party/* --exclude=/usr/include/* --output-file "$COVERAGE_ROOT/lcov_base.info"
lcov --gcov-tool $CHIP_ROOT/cov_clang.sh --capture --directory "$OUTPUT_ROOT/obj/third_party/connectedhomeip/src" --exclude="$OUTPUT_ROOT/obj/third_party/connectedhomeip"/zzz_generated/* --exclude="$OUTPUT_ROOT/obj/third_party/connectedhomeip"/third_party/* --exclude=/usr/include/* --output-file "$COVERAGE_ROOT/lcov_test.info"
lcov --gcov-tool $CHIP_ROOT/cov_clang.sh --add-tracefile "$COVERAGE_ROOT/lcov_base.info" --add-tracefile "$COVERAGE_ROOT/lcov_test.info" --output-file "$COVERAGE_ROOT/lcov_final.info"
genhtml "$COVERAGE_ROOT/lcov_final.info" --output-directory "$COVERAGE_ROOT/html"

zip -9 -y -r -q "$CHIP_ROOT/$COVERAGE_NAME.zip" $COVERAGE_ROOT
