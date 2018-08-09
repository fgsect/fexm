import argparse
import shlex
import subprocess
import sys
import threading
import time

import os
from shutil import copyfile


def signal_term_handler(signal, frame):
    global aflfuzzerprocess
    global syncqueue
    if syncqueue:
        syncqueue.alive = False
        syncqueue._stop()
    print('got SIGTERM')
    print(aflfuzzerprocess)
    if aflfuzzerprocess:
        print("Killing fuzzer process")
        aflfuzzerprocess.kill()
    sys.exit(0)


def get_afl_metadata(afl_dir_path) -> {}:
    fuzzer_stats_dict = {}
    try:
        # print(afl_dir_path+"/fuzzer_stats")
        with open(afl_dir_path + "/fuzzer_stats") as package_info_filepointer:
            text = package_info_filepointer.read()
            tmp_list = [item.strip().split(":", 1) for item in text.split("\n")]
            for item in tmp_list:
                # print(tmp_list)
                if len(item) == 2:
                    fuzzer_stats_dict[item[0].strip()] = item[1].strip()
        # print(fuzzer_stats_dict)
        return fuzzer_stats_dict
    except FileNotFoundError:
        return None


class SyncQueue(threading.Thread):
    def __init__(self, fuzzer_dir: str, target_dir: str):
        threading.Thread.__init__(self)
        self.fuzzer_dir = fuzzer_dir
        self.queue_dir = os.path.join(self.fuzzer_dir, "queue")
        self.target_dir = target_dir
        if not os.path.exists(self.target_dir):
            os.makedirs(self.target_dir, exist_ok=True)
        self.alive = True

    def run(self):
        while self.alive:
            time.sleep(5)  # sleep five seconds
            copy_to_dir = os.path.join(self.target_dir, "queue" + str(int(time.time())))
            os.mkdir(copy_to_dir)
            src_files = os.listdir(self.queue_dir)
            for file in src_files:
                if os.path.isfile(os.path.join(self.queue_dir, file)):
                    copyfile(os.path.join(self.queue_dir, file), copy_to_dir + "/" + file)

    def _stop(self):
        self.alive = False


def main(invocation: str, queue_dir: str):
    global aflfuzzerprocess
    global SyncQueue
    output_argument_idx = shlex.split(invocation).index("-o")
    afl_out_dir = shlex.split(invocation)[output_argument_idx + 1]
    print("out dir", afl_out_dir)
    print("queue dir", queue_dir)
    print("afl-fuzz " + invocation)
    syncqueue = SyncQueue(afl_out_dir, queue_dir)
    syncqueue.start()
    import sh
    aflfuzz = sh.Command("afl-fuzz")
    try:
        aflfuzzerprocess = subprocess.Popen(shlex.split("timeout 5m afl-fuzz " + invocation), shell=False)
        aflfuzzerprocess.wait()
    except Exception as e:
        syncqueue.alive = False
        print(e)
    syncqueue.alive = False
    syncqueue._stop()


if __name__ == "__main__":
    global aflfuzzerprocess
    global aflfuzzerprocess
    aflfuzzerprocess = None
    syncqueue = None
    parser = argparse.ArgumentParser(description='Evaluation helper script.')
    parser.add_argument("-i", "--invocation", required=True, type=str, help="The invocation for the fuzzer.",
                        default=None)
    parser.add_argument("-q", "--qdir", required=True, type=str, help="Where should the queue be stored?.",
                        default=None)
    args = parser.parse_args()
    try:
        main(args.invocation, args.qdir)
    except KeyboardInterrupt:
        print("Keyboard")
        signal_term_handler(1, 1)
