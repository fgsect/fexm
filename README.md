# FuzzExMachina 

![FExM](fexm.svg?raw=true)
FExM simplifies basic fuzzing pipelines. As result of years of practical fuzz testing, it provides a best effort approach 
able to get running quickly and finding bugs in most applications. 
Given its fully automated nature, it can be used to fuzz complete software repositories and distributions as well as single programs.


## Getting Started

These instructions guide you through your first fuzz test using FExM. 

### Prerequisites

Right now, FuzzExMachina runs natively on Ubuntu Linux (18.04). 

If you just want to try it out, we provide a vagrant vm with the correct environment for easy setup.
The Dockerfile provided might also work but at this point is pretty untested.

To use Vagrant please [install Vagrant](https://www.vagrantup.com/docs/installation/),
the Virtualbox provider and nfs.

- Software
  - [vagrant](https://www.vagrantup.com/downloads.html) (Tested with v2.1.2)
  - [virtualbox](https://www.virtualbox.org/wiki/Linux_Downloads) (Tested with v5.2.14)
- Recommended Vargant Plugins (install with `vagrant plugin install <name>`)
  - [vagrant-disksize](https://github.com/sprotheroe/vagrant-disksize)  -> More space inside Vagrant disks
  - [vagrant-winnfsd](https://github.com/winnfsd/vagrant-winnfsd)  -> Shared folders via NFS (Windows only)
  - [network file system] sudo apt-get install nfs-common
- Hardware
  - 8GB RAM+
  - Sufficient disk space (== a lot)
  - 8 logical CPUs (or adapt the Vagrantfile manually)
  
### Installation

To get running using Vagrant, simply
```sh
git clone git@github.com/fgsect/fexm.git
cd fexm && vagrant up
vagrant ssh
```

For a manual setup (intrusive!), run `./fexm/scripts/setup.sh`. It performs the following steps:
1. Install docker
2. Install RabbitMQ
3. Creates the FExM virtualenv in `~/.virtualenvs` (for virtualenvwrapper) 
    and installs the packages from `./fexm/requirements.txt` inside venv

### Fuzzing
    
#### No Seeds, no Fuzz
First, you will need to acquire seeds that will then be fed into the FExM.

For this, FExM provides a github crawler.

To do that, create an an [auth token](https://github.com/settings/tokens) at GitHub.
   
Afterwards, run 
```sh
./fexm/fexm crawl -a <GitHub AUTHTOKEN> -o <PathToSeeds>`
```
Inside vagrant, you can simply run:
```sh 
fexm crawl -a <GitHub AUTHTOKEN> 
```
 
#### Run Rabbit, Run

After creating the seeds, it's time to fuzz. FExM is configured via json. 
The following is a commented version of a json configuration file:

```json
{
  "name": "top500", // The name of our fuzzing run
  "fuzz_manager": "pacman", // What fuzz manager to use (inside ./)
  "packages_file": "/fexm/examples/top500.txt", // for pacman fuzzer: top500.txt
  "base_image": "pacmanfuzzer" // the base docker image to use
}
```

- Set up pacmanfuzzer docker image

Pacmanfuzzer is an example fuzzer that will fuzz the arch upstream repositories.

```sh
fexm init pacmanfuzzer
```

Verify that the docker image has been set up in the previous step

```sh
$ docker images -a | grep pacmanfuzzer
pacmanfuzzer        latest              489673de5625        About a minute ago   2.98GB
```

We provide an example json that will fuzz the top500 tools from the Arch repos as `top500.json`.
```sh
fexm fuzz ./examples/top500.json
```

This will then spawn the 
2. Another one for the example python script. 
Your results will be stored in the out directory.

#### Results

To display the results in the dashboard, open [http://localhost:5307](http://localhost:5307) in your browser. 

## Fork, Star, PRs, Issues

If you liked the demo, check out the source code of [FExM](https://github.com/fgsect/fexm).
Forking and starring is highly welcome!
We would like FExM to be free and open source, and most importantly useful to you.
Since we have limited resources to maintain code and add new features, we encourage you to send pull requests for bug fixes and new features :-)

## Digging Deeper 
### Debugging the Docker
1. To connect to the docker container do: 

```sh
docker run -ti --entrypoint /bin/bash --privileged pacmanfuzzer
--privileged is need for strace and asan.
```

Now you are inside the docker!

To build a package with afl, do:

```sh
aflize package
```

or even better, use the python script:

```sh
fexm/configfinder/builder_wrapper.py -p <package>
```

To fuzz, just use afl-fuzz as you would normaly do. Seeds are in the `/tmp/seeds/`, dictionaries are in `/fuzz_dictionaries/dictionaries/`

To mount your current path as volume, do:

```sh
docker run -v "$(pwd):/results" -ti --entrypoint /bin/bash --privileged pacmanfuzzer
```

To use the detailed tooling, spawn up a celery instance:

```sh
cd /fexm/celery_tasks 
celery -A tasks 
```

You can now use the tools (for more information call `-h` on each tool):

```sh
python fexm/tools/inference_manager_pacman.py -cd syncdir -di pacmanfuzzer
pyhton fexm/fuzz_manager/fuzz_manager_round_robin.py -cd syncdir -di pacmanfuzzer -t <afl -t option>
# Inferring input vectors
```

### Run inputinferance
To infer the input vector for a given binary, execute:

```sh
$ /fexm/configfinder/config_finder_for_binary.py -b tcpdump -s /seeds
[...]
#########################################################################
Input vector for tcpdump is most likely:
-nr @@
/seeds/pcap_samples
```

The tool will automatically figure out when QEMU is required.

## FAQ
Q: I get `pull access denied for pacmanfuzzer, repository does not exist or may require 'docker login'` 
   when trying to fuzz.
   
A: You need to run `fexm init pacmanfuzzer` once before fuzzing.

## Authors

* **Vincent Ulitzsch** - [@viniul](https://github.com/viniul)
* **Dominik Maier** - [@domenukk](https://github.com/domenukk)
* **Bhargava Shastry** - [@bshastry](https://github.com/bshastry)

See also the list of [contributors](https://github.com/fgsect/fexm/contributors) who participated in this project.

## License

This project is licensed under the APACHE v2 License - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments

* rc0r for AFL-Utils
* jfoote for exploitable
* Lots of groundwork on preeny was done by @zardus 
* @lcamtuf for AFL (obviously)
* Some initial work for the pcap parser was stolen (with permission) from Ben Stock (@kcotsneb)  
* The GitHub crawler makes use of [sourcecode](https://github.com/tommiu/GithubSpider) by Tommi Unruh
* So many more...
