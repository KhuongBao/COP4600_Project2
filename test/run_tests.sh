#!/usr/bin/env bash
# ==============================================================================
# COP4600 Project 2 - Automated Test & Benchmark Script
# Person C: Test Suite & Performance Evaluation
#
# This script executes all three Gradescope test cases (data1, data2, data3),
# verifies correctness against expected output, records execution time, and
# computes speedup relative to the unthreaded baseline reference.
# ==============================================================================

set -e

# ANSI Color Codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Determine repository root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SRC_DIR="${ROOT_DIR}/src"
TEST_DIR="${ROOT_DIR}/test"
EXECUTABLE="${SRC_DIR}/project2"

echo -e "${BOLD}${CYAN}======================================================${NC}"
echo -e "${BOLD}${CYAN}       COP4600 Project 2: Test & Benchmark Suite      ${NC}"
echo -e "${BOLD}${CYAN}======================================================${NC}"

# Ensure executable is built
if [ ! -f "${EXECUTABLE}" ]; then
    echo -e "${YELLOW}Executable not found. Building project2...${NC}"
    make -C "${SRC_DIR}"
fi

# Baseline reference execution times (in seconds)
# Reference values from single-threaded baseline run
BASE_TIME_DATA1=2.985
BASE_TIME_DATA2=5.741
BASE_TIME_DATA3=27.931

# Temporary directory for test outputs
TMP_DIR=$(mktemp -d /tmp/cop4600_test_XXXXXX)
trap 'rm -rf "${TMP_DIR}"' EXIT

ALL_PASSED=1

declare -a TEST_NAMES=("data1" "data2" "data3")
declare -a BASE_TIMES=(${BASE_TIME_DATA1} ${BASE_TIME_DATA2} ${BASE_TIME_DATA3})
declare -a ACTUAL_TIMES=()
declare -a TEST_STATUS=()
declare -a SPEEDUPS=()

for i in "${!TEST_NAMES[@]}"; do
    NAME="${TEST_NAMES[$i]}"
    BASE_T="${BASE_TIMES[$i]}"
    CASE_DIR="${TEST_DIR}/${NAME}"
    PW_FILE="${CASE_DIR}/common-passwords.txt"
    HASH_FILE="${CASE_DIR}/hashes.txt"
    EXP_FILE="${CASE_DIR}/expected.txt"
    OUT_FILE="${TMP_DIR}/${NAME}_output.txt"

    echo ""
    echo -e "${BOLD}Running Test Case: ${CYAN}${NAME}${NC}..."
    if [ ! -f "${PW_FILE}" ] || [ ! -f "${HASH_FILE}" ] || [ ! -f "${EXP_FILE}" ]; then
        echo -e "${RED}Error: Test files for ${NAME} missing!${NC}"
        ALL_PASSED=0
        TEST_STATUS+=("MISSING")
        ACTUAL_TIMES+=("N/A")
        SPEEDUPS+=("N/A")
        continue
    fi

    # Run executable and capture printed elapsed time
    EXEC_TIME=$("${EXECUTABLE}" "${PW_FILE}" "${HASH_FILE}" "${OUT_FILE}")
    ACTUAL_TIMES+=("${EXEC_TIME}")

    # Verify correctness by diffing output with expected
    if diff -u --strip-trailing-cr "${EXP_FILE}" "${OUT_FILE}" > "${TMP_DIR}/${NAME}_diff.txt"; then
        echo -e "  Correctness:  ${GREEN}[PASS] Output matches expected.txt${NC}"
        TEST_STATUS+=("PASS")
    else
        echo -e "  Correctness:  ${RED}[FAIL] Output does not match expected.txt!${NC}"
        echo -e "${YELLOW}Diff output:${NC}"
        head -n 20 "${TMP_DIR}/${NAME}_diff.txt"
        ALL_PASSED=0
        TEST_STATUS+=("FAIL")
    fi

    # Compute speedup factor
    SPEEDUP=$(awk "BEGIN {printf \"%.2f\", ${BASE_T} / ${EXEC_TIME}}")
    SPEEDUPS+=("${SPEEDUP}x")

    echo -e "  Elapsed Time: ${BOLD}${EXEC_TIME}s${NC} (Baseline: ${BASE_T}s)"
    echo -e "  Speedup:      ${GREEN}${BOLD}${SPEEDUP}x${NC}"
done

echo ""
echo -e "${BOLD}${CYAN}======================================================${NC}"
echo -e "${BOLD}${CYAN}                  SUMMARY RESULTS                     ${NC}"
echo -e "${BOLD}${CYAN}======================================================${NC}"
printf "%-10s | %-8s | %-12s | %-12s | %-10s\n" "Test Case" "Status" "Baseline (s)" "Actual (s)" "Speedup"
echo "------------------------------------------------------------"

for i in "${!TEST_NAMES[@]}"; do
    NAME="${TEST_NAMES[$i]}"
    STATUS="${TEST_STATUS[$i]}"
    BASE_T="${BASE_TIMES[$i]}"
    ACT_T="${ACTUAL_TIMES[$i]}"
    SPD="${SPEEDUPS[$i]}"

    if [ "${STATUS}" == "PASS" ]; then
        STATUS_FMT="${GREEN}PASS${NC}"
    else
        STATUS_FMT="${RED}${STATUS}${NC}"
    fi

    printf "%-10s | %-17b | %-12s | %-12s | %-10s\n" "${NAME}" "${STATUS_FMT}" "${BASE_T}" "${ACT_T}" "${SPD}"
done

echo "------------------------------------------------------------"
echo -e "${BOLD}Target Rubric Speedup: 4.3x or higher for max 50 points.${NC}"

if [ ${ALL_PASSED} -eq 1 ]; then
    echo -e "\n${GREEN}${BOLD}ALL TESTS PASSED! Project is ready for submission.${NC}\n"
    exit 0
else
    echo -e "\n${RED}${BOLD}SOME TESTS FAILED! Review diff outputs above.${NC}\n"
    exit 1
fi
