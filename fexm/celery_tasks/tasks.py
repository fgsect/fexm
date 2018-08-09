import json
import logging
import sys
import typing
import uuid
from typing import List

import docker
import docker.api.container
import os
import sh
from celery import Celery
from sh import docker as docker_command
from celery.contrib.abortable import AbortableTask

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from helpers.utils import init_logger
import helpers.docker_builder

logger = init_logger("tasks", use_celery=True)

"""
This file contains all the task descriptions for celery 
"""

app = Celery('celery_tasks.tasks', backend='rpc://', broker='pyamqp://guest@localhost//')
KEEP_IMAGES = False
docker_client = docker.from_env()


@app.task(bind=True, base=AbortableTask, name="celery_tasks.tasks.run_fuzzer")
def run_fuzzer(self, docker_name, package: str, docker_args: [str], base_image: str, build_file: str,
               fuzzer_command_args: [str], timeout_per_package: float) -> (str, bool):
    fuzzer_command = None
    from celery.platforms import signals

    def int_handler(signum, frame):
        print("Int handler!")
        if fuzzer_command is not None:
            try:
                docker_command.stop(docker_name,
                                    _timeout=120)  # It should not take longer than 120 seconds to kill a docker container, right????
            except sh.ErrorReturnCode:
                return package, True
            except sh.TimeoutException:  # It took too long too kill the docker container - we are going to ignore that for now, we want to continue fuzzing
                return package, True
            return package, True
        else:
            return package, True

    signals['INT'] = int_handler
    try:
        if os.path.exists(build_file):
            with open(build_file, "r") as jsonfp:
                build_dict = json.load(jsonfp)
                package_image_name = build_dict["docker_image_name"]
        else:
            package_image_name = package + "_" + str(uuid.uuid4())[:8]
        # TODO: Limit build process to one cpu
        package_image_name = helpers.docker_builder.return_current_package_image(package=package,
                                                                                 fuzzer_image=base_image,
                                                                                 package_image=package_image_name,
                                                                                 json_output_path=build_file)
        if package_image_name is None:
            return False
        # docker_args.insert(0,'--cpus=0.90')
        print("Invoking the fuzzing docker")
        # TODO: This throws an exception in the background thread right now, which seems to be a bug in sh:
        # https://github.com/amoffat/sh/issues/399. For now, we are ignoring the issue.
        fuzzer_command = docker_command.run(docker_args, package_image_name, fuzzer_command_args, _out=sys.stdout,
                                            _bg=True, _timeout=timeout_per_package)
        fuzzer_command.wait()
        if fuzzer_command.exit_code != 0:
            print("Something went wrong for package {0}", package)
            return package, False
        print("Done! Returning True")
        return package, True
    except sh.ErrorReturnCode as e:
        print("afl-fuzz error:")
        print("STDOUT:\n", e.stdout.decode("utf-8"))
        print("STDERR:\n", e.stderr.decode("utf-8"))
        print("command line: {0}".format(e.full_cmd))
        return package, False
    except sh.TimeoutException as e:
        print("Fuzzing {0} timed out... Next one!".format(package))
        try:
            docker_command.stop(docker_name)
        except sh.ErrorReturnCode as e:  # Container is already removed
            pass
        return package, True
    except sh.SignalException_SIGKILL as e:
        print("Killed")
        return package, True
    return package, True


@app.task(bind=True, base=AbortableTask, name="celery_tasks.tasks.run_minimizer")
def run_minimizer(self, docker_name, package: str, docker_args: [str], fuzzer_image: str, build_file: str,
                  fuzzer_command_args: [str], timeout_per_package: float) -> (str, bool):
    minimizer_command = None
    from celery.platforms import signals

    def int_handler(signum, frame):
        print("Int handler!")
        if minimizer_command is not None:
            try:
                docker_command.stop(docker_name,
                                    _timeout=120)  # It should not take longer than 120 seconds to kill a docker container, right????
            except sh.ErrorReturnCode:
                return package, True
            except sh.TimeoutException:  # It took too long too kill the docker container - we are going to ignore that for now, we want to continue fuzzing
                return package, True
            return package, True
        else:
            return package, True

    signals['INT'] = int_handler
    try:
        if os.path.exists(build_file):
            with open(build_file, "r") as jsonfp:
                build_dict = json.load(jsonfp)
                package_image_name = build_dict["docker_image_name"]
        else:
            package_image_name = package + "_" + str(uuid.uuid4())[:8]
        package_image_name = helpers.docker_builder.return_current_package_image(package=package,
                                                                                 fuzzer_image=fuzzer_image,
                                                                                 package_image=package_image_name,
                                                                                 json_output_path=build_file)
        docker_args.insert(0, '--cpus=1.0')
        print("Invoking the minimizing docker")
        minimizer_command = docker_command.run(docker_args, package_image_name, fuzzer_command_args, _out=sys.stdout,
                                               _bg=True)  # No timeout here, the timeouts are build into the minimizer
        minimizer_command.wait()
        if minimizer_command.exit_code != 0:
            print("Some went wrong for package {0}", package)
            return package, False
        print("Done! Returning True")
        return package, True
    except sh.ErrorReturnCode as e:
        print("Minimizer error:")
        print("STDOUT:\n", e.stdout.decode("utf-8"))
        print("STDERR:\n", e.stderr.decode("utf-8"))
        print("command line: {0}".format(e.full_cmd))
        return package, False
    except sh.TimeoutException as e:
        print("Minimizing {0} timed out... Next one!".format(package))
        return package, True
    except sh.SignalException_SIGKILL as e:
        print("Killed")
        return package, True
    return package, True


@app.task(bind=True, base=AbortableTask, name="celery_tasks.tasks.run_inference")
def run_inference(self, docker_name, package: str, docker_args: [str], fuzzer_image: str, build_file: str,
                  inference_command_args: List[str], timeout_per_package: float, qemu: bool = False):
    """
    :param self: 
    :param docker_name: 
    :param package: 
    :param docker_args: 
    :param fuzzer_image: 
    :param build_file: 
    :param inference_command_args: 
    :param timeout_per_package: 
    :type inference_command_args: List
    :return: 
    """
    inference_command = None
    from celery.platforms import signals

    def int_handler(signum, frame):
        print("Int handler!")
        if inference_command is not None:
            try:
                docker_command.stop(docker_name,
                                    _timeout=120)  # It should not take longer than 120 seconds to kill a docker container, right????
            except sh.ErrorReturnCode:
                return True
            except sh.TimeoutException:  # It took too long too kill the docker container - we are going to ignore that for now, we want to continue fuzzing
                return True
            return True
            # fuzzer_command.kill()
            # fuzzer_command.wait()
        else:
            return True

    signals['INT'] = int_handler
    print("Now working on {0}".format(package))
    try:
        if os.path.exists(build_file):
            with open(build_file, "r") as jsonfp:
                build_dict = json.load(jsonfp)
                package_image_name = build_dict["docker_image_name"]
        else:
            package_image_name = package + "_" + str(uuid.uuid4())[:8]
        if not os.path.exists(os.path.dirname(build_file)):
            os.mkdir(os.path.dirname(build_file))
        # TODO: There is an issue with qemu here. Fix this!
        package_image_name = helpers.docker_builder.return_current_package_image(package=package,
                                                                                 fuzzer_image=fuzzer_image,
                                                                                 package_image=package_image_name,
                                                                                 json_output_path=build_file, qemu=qemu)
        print("docker run", " ".join(docker_args), package_image_name,
              " ".join(map(lambda x: str(x), inference_command_args)))
        build_dict = {}
        with open(build_file) as build_filefp:
            build_dict = json.load(build_filefp)
        if build_dict["qemu"] and "-Q" not in inference_command_args:
            inference_command_args.append("-Q")
        elif not build_dict["qemu"] and "-Q" in inference_command_args:
            inference_command_args.remove("-Q")
        docker_args.insert(0, '--cpus=1.0')
        inference_command = docker_command.run(docker_args, package_image_name, inference_command_args, _out=sys.stdout,
                                               _timeout=timeout_per_package)  # type: sh.RunningCommand
        if inference_command.exit_code != 0:
            print("Some went wrong for package {0}", package)
            return False
        if not KEEP_IMAGES:
            docker_command.rmi("-f", package_image_name)

        print("Done! Returning True")
        return True
    except sh.ErrorReturnCode as e:
        print("Inference error:")
        print("STDOUT:\n", e.stdout.decode("utf-8"))
        print("STDERR:\n", e.stderr.decode("utf-8"))
        print("command line: {0}".format(e.full_cmd))
        logger.error("Inference error:")
        logger.error("STDOUT:\n", e.stdout.decode("utf-8"))
        logger.error("STDERR:\n", e.stderr.decode("utf-8"))
        logger.error("command line: {0}".format(e.full_cmd))
        return False
    except sh.TimeoutException as e:
        print("Inferring {0} timed out... Next one!".format(package))
        return True
    except sh.SignalException_SIGKILL as e:
        print("Killed")
        return True
    return True


@app.task(bind=True, base=AbortableTask, name="celery_tasks.tasks.build_package")
def build_package(self, package: str, fuzzer_image: str, build_file: str, qemu: bool = False):
    if os.path.exists(build_file):
        with open(build_file, "r") as jsonfp:
            build_dict = json.load(jsonfp)
            package_image_name = build_dict["docker_image_name"]
    else:
        package_image_name = package + "_" + str(uuid.uuid4())[:8]
    if not os.path.exists(os.path.dirname(build_file)):
        os.mkdir(os.path.dirname(build_file))
    # TODO: There is an issue with qemu here. Fix this!
    package_image_name = helpers.docker_builder.return_current_package_image(package=package, fuzzer_image=fuzzer_image,
                                                                             package_image=package_image_name,
                                                                             json_output_path=build_file, qemu=qemu,
                                                                             timeout=30 * 60)
    return package_image_name


@app.task(bind=True, name="celery_tasks.tasks.run_eval")
def run_eval(self, package: str, fuzzer_image: str, volume_path: str, seeds_path: str, fuzz_duration: int = 45 * 60,
             use_asan: int = False, exec_timeout: int = None, qemu: bool = False,
             config_dict: typing.Dict[str, object] = None):
    """

    :param self:
    :param package:
    :param fuzzer_image:
    :param volume_path:
    :param seeds_path:
    :param fuzz_duration:
    :param use_asan:
    :param exec_timeout:
    :param qemu:
    :param config_dict:
    :return:
    """
    print("Got eval task for package {0}".format(package))
    logger.info("Got eval task for package  {0}".format(package))
    volumes_dict = {
        os.path.join(volume_path, "fuzz_data"): {"bind": "/results", "mode": "rw"},
        os.path.join(volume_path, "build_data"): {"bind": "/build", "mode": "rw"},
        os.path.join(volume_path, "run_configurations"): {"bind": "/run_configurations", "mode": "ro"},
        seeds_path: {"bind": "/fuzz/seeds", "mode": "ro"},
    }
    additional_env_variables = {}
    if use_asan:
        additional_env_variables["AFL_USE_ASAN"] = "1"
    eval_package_dict = {"package": package, "volume": "/results", "fuzz_duration": int(fuzz_duration),
                         "exec_timeout": exec_timeout, "qemu": qemu, "seeds": "/fuzz/seeds",
                         "fuzzing_cores_per_binary": config_dict.get("fuzzing_cores_per_binary"), "asan": use_asan}
    os.makedirs(os.path.join(volume_path, "run_configurations"), exist_ok=True)
    with open(os.path.join(volume_path, "run_configurations", package + ".json"), "w") as fp:
        json.dump(eval_package_dict, fp, indent=4, sort_keys=True)
    eval_args = ["/inputinferer/configfinder/eval_package.py", "/run_configurations/" + package + ".json"]
    container = docker_client.containers.run(image=fuzzer_image, remove=True, cap_add=["SYS_PTRACE"],
                                             security_opt=["seccomp=unconfined"],
                                             entrypoint="python",
                                             volumes=volumes_dict,
                                             command=eval_args,
                                             detach=True, stream=True, stdout=True, stderr=True,
                                             name=package + "_fuzz_" + str(uuid.uuid4())[:4],
                                             environment=additional_env_variables)
    container_output = ""
    for line in container.logs(stream=True):
        logger.info(line.decode("utf-8").strip())
        container_output += line.decode("utf-8")
    status = container.wait()
    if status["StatusCode"] != 0:
        logger.error(
            "Error while running docker command. Docker Output:\n {0}. Return value {1}".format(container_output,
                                                                                                status["StatusCode"]))
        return False
    return True


@app.task(bind=True, name="celery_tasks.tasks.analyze_package")
def analyze_package(self, fuzzer_image: str, volume_path: str, package: str):
    """

    :param self:
    :param package:
    :param fuzzer_image:
    :param volume_path:
    :param seeds_path:
    :param fuzz_duration:
    :param use_asan:
    :param exec_timeout:
    :param qemu:
    :param config_dict:
    :return:
    """
    volumes_dict = {
        os.path.abspath(os.path.join(volume_path, "fuzz_data")): {"bind": "/results", "mode": "rw"},
        os.path.abspath(os.path.join(volume_path, "build_data")): {"bind": "/build", "mode": "rw"},
    }
    logging.info("Now analyzing crashes for {0}".format(package))
    analyze_command_params = ["/inputinferer/configfinder/analyze_wrapper.py", "-p", package, "-v", "/results/",
                              "package"]
    container = docker_client.containers.run(image=fuzzer_image, remove=False, privileged=True, entrypoint="python",
                                             volumes=volumes_dict,
                                             command=analyze_command_params,
                                             detach=True, stream=True, stdout=True, stderr=True,
                                             name=package + "_analyze_" + str(uuid.uuid4())[:4])
    container_output = ""
    for line in container.logs(stream=True):
        logging.info(line.decode("utf-8").strip())
        container_output += line.decode("utf-8")
    status = container.wait()
    if status["StatusCode"] != 0:
        logging.info(
            "Error while running docker command. Docker Output:\n {0}. Return value {1}".format(container_output,
                                                                                                status[
                                                                                                    "StatusCode"]))
        return False
    return True


@app.task(bind=True, name="celery_tasks.tasks.run_asan_eval")
def run_asan_eval(self, package: str, fuzzer_image: str, volume_path: str):
    """
    :param self:
    :param docker_name:
    :param package:
    :param docker_args:
    :param fuzzer_image:
    :param build_file:
    :param inference_command_args:
    :param timeout_per_package:
    :type inference_command_args: List
    :return:
    """
    print("Got eval task for package {0}".format(package))
    logger.info("Got eval task for package  {0}".format(package))
    volumes_dict = {
        volume_path: {"bind": "/results", "mode": "rw"},
    }
    additional_env_variables = {"AFL_USE_ASAN": "1"}
    container = docker_client.containers.run(image=fuzzer_image, remove=True, privileged=True, entrypoint="python",
                                             volumes=volumes_dict,
                                             command=["/inputinferer/configfinder/asan_crash_analyzer.py", "-p",
                                                      package, "-v", "/results"],
                                             detach=True, stream=True, stdout=True, stderr=True,
                                             name=package + "_fuzz_" + str(uuid.uuid4())[:4],
                                             environment=additional_env_variables)  # type: docker.api.container
    container_output = ""
    for line in container.logs(stream=True):
        logger.info(line.decode("utf-8").strip())
        container_output += line.decode("utf-8")
    status = container.wait(timeout=600)  # Set a really high timeout
    if status["StatusCode"] != 0:
        logger.error(
            "Error while running docker command. Docker Output:\n {0}. Return value {1}".format(container_output,
                                                                                                status["StatusCode"]))
        return False

        # print("Exception: {0}".format(e))
    # inference_command = None
    # print("Now working on {0}".format(package))
    # docker_args = ["--privileged","--rm","-v",volume_path+":/results","--entrypoint","python",fuzzer_image,"/inputinferer/configfinder/eval_package.py","-p",package,"-v","/results"]
    # docker.run(docker_args,_out=sys.stdout)
    return True
