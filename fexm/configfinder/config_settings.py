import os
from enum import IntEnum

MAX_TIMEOUT_PER_PACKAGE = 25 * 60  # 25 Minutes should be enough
MAX_TIMEOUT_BINARY_INFERENCE = 60 * 60  # 15 Minutes per Binary should be enough
MAX_TIMEOUT_PACKAGE_INFERENCE = 1000 * 60  # Essentiallly no limit
FAILED_INVOCATIONS_THRESHOLD = 10  # How much invocations can fail before we skip the binary?
MEMORY_LIMIT = "none"  # The memory limit
AFL_CMIN_TIMEOUT = 10 * 60  # Timeout for cmin run
AFL_CMIN_INVOKE_TIMEOUT = 3  # 1 Second
AFL_TMIN_INVOKE_TIMEOUT = 1  # 1 Second
AFL_TMIN_TIMEOUT = 1 * 60  # Total timeout for tmin run - 10 minutes. tmin does not help much, except for the case where we got the wrong filetype,
#                          where it completely minimizes our file!
MAX_BUILD_TRESHOLD = 31854592  # Do not build packages above 31854592
MAX_INSTALL_TRESHOLD = 20000576  # Do not consider packages above 20000 MB
BUILD_TIMEOUT = 300 * 60  # 5 hours building time
MEM_LIMIT = 0  # The memory limit for afl-fuzz. None for using the default, 0 for no memory limit
BUILDER_BUILD_FAILED = -1
BUILDER_BUILD_NORMAL = 1
BUILDER_BUILD_QEMU = 2

aflerrors = {"AFL_ALREADY_INSTRUMENTED": "Instrumentation found in -Q mode",
             "AFL_NOT_INSTRUMENTED": "No instrumentation detected",
             "AFL_NOT_INSTRUMENTED_ALTERNATIVE": "doesn't appear to be instrumented.",
             "AFL_TIMEOUT": "Target binary times out"}
PREENY_PATH = "/preeny"


class Status(IntEnum):
    INFERENCE_DONE = 1
    MINIMIZE_DONE = 2
    FUZZING = 3


newenv = os.environ.copy()
newenv["AFL_BIN_PATH"] = "/usr/local/bin"
newenv["AFL_SKIP_CPUFREQ"] = "1"
newenv["AFL_INST_LIBS"] = "1"
newenv["AFL_EXIT_WHEN_DONE"] = "1"
newenv["ASAN_OPTIONS"] = (
    "detect_leaks=0:"  # Do not detect leaks, this can prevent projects from being build!
    "detect_odr_violation=0:"  # Do not detect one definition violations, those are not of interest to us
    "abort_on_error=1:"  # Do not detect one definition violations, those are not of interest to us
    "symbolize=0:"  # Do not detect one definition violations, those are not of interest to us
    "allocator_may_return_null=1"  # Do not detect one definition violations, those are not of interest to us
)
newenv["AFL_ALLOW_TMP"] = "1"
newenv["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"


def get_inference_env_without_desock():
    inference_env = newenv.copy()
    inference_env["LD_PRELOAD"] = " " + os.path.join(PREENY_PATH, "src/desrand.so")
    inference_env["LD_PRELOAD"] += " " + os.path.join(PREENY_PATH, "src/derand.so")
    return inference_env


def get_inference_env_with_desock():
    inference_env = newenv.copy()
    inference_env["LD_PRELOAD"] = "{} {} {}".format(
        os.path.join(PREENY_PATH, "src/desock_vincent.so"),
        os.path.join(PREENY_PATH, "src/desrand.so"),
        os.path.join(PREENY_PATH, "src/derand.so")
    )
    return inference_env


def get_fuzzing_env_without_desock():
    fuzzing_env = newenv.copy()
    fuzzing_env["AFL_PRELOAD"] = " " + os.path.join(PREENY_PATH, "src/desrand.so")
    fuzzing_env["AFL_PRELOAD"] += " " + os.path.join(PREENY_PATH, "src/derand.so")
    return fuzzing_env


def get_fuzzing_env_with_desock():
    fuzzing_env = newenv.copy()
    fuzzing_env["AFL_PRELOAD"] = os.path.join(PREENY_PATH, "src/desock_vincent.so")
    fuzzing_env["AFL_PRELOAD"] += " " + os.path.join(PREENY_PATH, "src/desrand.so")
    fuzzing_env["AFL_PRELOAD"] += " " + os.path.join(PREENY_PATH, "src/derand.so")
    return fuzzing_env
