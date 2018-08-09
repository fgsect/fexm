import argparse
import logging
import sys

import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from builders import builder

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Controller for the fuzzing framework.')
    subparsers = parser.add_subparsers(help='sub-command help.', dest="command")
    subparsers.required = True
    minimize_parser = subparsers.add_parser("minimize", help="Minimize seeds for a binary")
    minimize_parser.add_argument("-p", "--package", required=True, type=str,
                                 help="The package to be examined. Must be a pacman package.")
    minimize_parser.add_argument("-Q", dest="qemu", action="store_true", default=False,
                                 help="Activate qemu mode when inferring file types.")
    minimize_parser.add_argument("-param", "--parameter", required=False, type=str,
                                 help="The parameter to the json file. Use = to pass hyphens(-)",
                                 default=None)  # Must exists in docker
    minimize_parser.add_argument("-s", "--seeds", required=True, type=str, help="Which seeds do we need?")
    minimize_parser.add_argument("-b", "--binary", required=False, type=str, help="Path to the binary to fuzz.")
    minimize_parser.add_argument("-v", "--output_volume", required=True, help="In which should the files be stored?")
    minimize_parser.add_argument("-n", "--name", required=False, help="The name of the docker container", default=None)
    minimize_parser.add_argument("-afile", "--afl_out_file", type=str, required=True,
                                 help="Where should the afl configuration be stored?")
    minimize_parser.add_argument("-tmintotal", "--tmin_total_time", type=int, required=False, default=None,
                                 help="For how long should tmin run in total at max?")
    minimize_parser.set_defaults(
        which='minimize')  # https://stackoverflow.com/questions/8250010/argparse-identify-which-subparser-was-used
    fuzz_parser = subparsers.add_parser("fuzz", help="Fuzz the binary")
    fuzz_parser.add_argument("-p", "--package", required=True, type=str,
                             help="The package to be examined. Must be a pacman package.")
    fuzz_parser.add_argument("-t", "--timeout", required=False, type=float, help="The timeout for afl",
                             default=None)  # Default timeout: 2 hours
    fuzz_parser.add_argument("-Q", dest="qemu", action="store_true", default=False,
                             help="Activate qemu mode when inferring file types.")
    fuzz_parser.add_argument("-param", "--parameter", required=False, type=str,
                             help="The parameter to the json file. Use = to pass hyphens(-)",
                             default=None)  # Must exists in docker
    fuzz_parser.add_argument("-s", "--seeds", required=False, type=str, help="Which seeds do we need?")
    fuzz_parser.add_argument("-b", "--binary", required=False, type=str, help="Path to the binary to fuzz.")
    fuzz_parser.add_argument("-v", "--output_volume", required=True, help="In which should the files be stored?")
    fuzz_parser.add_argument("-n", "--name", required=False, help="The name of the docker container", default=None)
    group = fuzz_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-adir", "--afl_resume_dir", help="Resume from afl out dir.")
    group.add_argument("-afile", "--afl_out_file", type=str,
                       help="Start over. Where should the afl configuration be stored/read from?")
    fuzz_parser.set_defaults(
        which='fuzz')  # https://stackoverflow.com/questions/8250010/argparse-identify-which-subparser-was-used
    eval_parser = subparsers.add_parser("evalfuzz", help="Evaluate the fuzzing for the binary")
    eval_parser.add_argument("-p", "--package", required=False, type=str,
                             help="The package to be examined. Must be a pacman package.")
    eval_parser.add_argument("-ft", "--fuzzer_timeout", required=False, type=float,
                             help="The timeout for afl (the whole fuzzer process)",
                             default=None)  # Default timeout: None ( take the one from config)
    eval_parser.add_argument("-t", "--timeout", required=False, type=float,
                             help="The timeout for afl (per run)",
                             default=None)  # Default timeout: None ( take the one from config)
    eval_parser.add_argument("-Q", dest="qemu", action="store_true", default=False,
                             help="Activate qemu mode when inferring file types.")
    eval_parser.add_argument("-param", "--parameter", required=False, type=str,
                             help="The parameter to the json file. Use = to pass hyphens(-)",
                             default=None)  # Must exists in docker
    eval_parser.add_argument("-s", "--seeds", required=True, type=str, help="Which seeds do we need?")
    eval_parser.add_argument("-b", "--binary", required=True, type=str, help="Path to the binary to fuzz.")
    eval_parser.add_argument("-v", "--output_volume", required=True, help="In which should the files be stored?")
    eval_parser.add_argument("-n", "--name", required=False, help="The name of the docker container", default=None)
    group = eval_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-afile", "--afl_out_file", type=str,
                       help="Start over. Where should the afl configuration be stored?")
    eval_parser.set_defaults(which="evalfuzz")
    args = parser.parse_args()
    logfilename = os.path.join(args.output_volume, args.package + ".log")
    logging.basicConfig(filename=logfilename, level=logging.INFO, format='%(levelname)s %(asctime)s: %(message)s',
                        filemode='a')
    parameter = None
    if args.parameter:
        if args.parameter[0] == '"' and args.parameter[-1] == '"':  # Parameter is enclosed by " ", we don't want that
            parameter = args.parameter[1:-1]
        else:
            parameter = args.parameter
    if args.which == "minimize" or args.which == "fuzz" or args.which == "eval":
        use_qemu = args.qemu
        b = builder.Builder(package=args.package, qemu=args.qemu)
        if not b.install():
            print("Could not install package, exiting")
            sys.exit(-1)
        use_qemu = b.qemu
    if args.which == "minimize":
        import minimzer

        minimzer.minize(parameter=parameter, seeds_dir=args.seeds, binary_path=args.binary, package=args.package,
                        volume_path=args.output_volume, afl_config_file_name=args.afl_out_file,
                        qemu=use_qemu, name=args.name, tmin_total_time=args.tmin_total_time)
    if args.which == "fuzz":
        use_qemu = args.qemu
        if args.afl_out_file:
            import fuzzer_wrapper

            res = fuzzer_wrapper.prepare_and_start_fuzzer(parameter=parameter, seeds_dir=args.seeds,
                                                          binary_path=args.binary, package=args.package,
                                                          volume_path=args.output_volume,
                                                          afl_config_file_name=args.afl_out_file, qemu=use_qemu,
                                                          name=args.name, timeout=args.timeout)
            if not res:
                sys.exit(-1)
        else:
            import fuzzer_wrapper

            res = fuzzer_wrapper.resume_fuzzer(afl_dir=args.afl_resume_dir, binary_path=args.binary,
                                               parameter=parameter, qemu=use_qemu, timeout=args.timeout)
            if not res:
                sys.exit(-1)
    if args.which == "evalfuzz":
        use_qemu = args.qemu
        from evalscripts import eval_fuzzing

        eval_fuzzing.eval_fuzzing(parameter=parameter, seeds=args.seeds, binary=args.binary, package=args.package,
                                  output_volume=args.output_volume, afl_out_file=args.afl_out_file, qemu=use_qemu,
                                  name=args.name, timeout=args.timeout, fuzzer_timeout=args.fuzzer_timeout)
