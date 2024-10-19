ONOS_IMG := onosproject/onos:2.2.2
P4RT_SH_IMG := p4lang/p4runtime-sh:latest
P4C_IMG := opennetworking/p4c:stable
MN_STRATUM_IMG := opennetworking/mn-stratum:latest
MAVEN_IMG := maven:3.6.1-jdk-11-slim
PTF_IMG := onosproject/fabric-p4test
GNMI_CLI_IMG := bocon/gnmi-cli:latest
YANG_IMG := bocon/yang-tools:latest

ONOS_SHA := sha256:438815ab20300cd7a31702b7dea635152c4c4b5b2fed9b14970bd2939a139d2a
P4RT_SH_SHA := sha256:6ae50afb5bde620acb9473ce6cd7b990ff6cc63fe4113cf5584c8e38fe42176c
P4C_SHA := sha256:8f9d27a6edf446c3801db621359fec5de993ebdebc6844d8b1292e369be5dfea
MN_STRATUM_SHA := sha256:ae7c59885509ece8062e196e6a8fb6aa06386ba25df646ed27c765d92d131692
MAVEN_SHA := sha256:ca67b12d638fe1b8492fa4633200b83b118f2db915c1f75baf3b0d2ef32d7263
PTF_SHA := sha256:227207ff9d15f5e45c44c7904e815efdb3cea0b4e5644ac0878d41dd54aca78d
GNMI_CLI_SHA := sha256:6f1590c35e71c07406539d0e1e288e87e1e520ef58de25293441c3b9c81dffc0
YANG_SHA := sha256:feb2dc322af113fc52f17b5735454abfbe017972c867e522ba53ea44e8386fd2

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
curr_dir := $(patsubst %/,%,$(dir $(mkfile_path)))
curr_dir_sha := $(shell echo -n "$(curr_dir)" | shasum | cut -c1-7)

app_build_container_name := app-build-${curr_dir_sha}
onos_url := http://localhost:8181/onos
onos_curl := curl --fail -sSL --user onos:rocks --noproxy localhost
app_name := org.onosproject.ngsdn-tutorial

default:
	$(error Please specify a make target (see README.md))

_docker_pull_all:
	docker pull ${ONOS_IMG}@${ONOS_SHA}
	docker tag ${ONOS_IMG}@${ONOS_SHA} ${ONOS_IMG}
	docker pull ${P4RT_SH_IMG}@${P4RT_SH_SHA}
	docker tag ${P4RT_SH_IMG}@${P4RT_SH_SHA} ${P4RT_SH_IMG}
	docker pull ${P4C_IMG}@${P4C_SHA}
	docker tag ${P4C_IMG}@${P4C_SHA} ${P4C_IMG}
	docker pull ${MN_STRATUM_IMG}@${MN_STRATUM_SHA}
	docker tag ${MN_STRATUM_IMG}@${MN_STRATUM_SHA} ${MN_STRATUM_IMG}
	docker pull ${MAVEN_IMG}@${MAVEN_SHA}
	docker tag ${MAVEN_IMG}@${MAVEN_SHA} ${MAVEN_IMG}
	docker pull ${PTF_IMG}@${PTF_SHA}
	docker tag ${PTF_IMG}@${PTF_SHA} ${PTF_IMG}
	docker pull ${GNMI_CLI_IMG}@${GNMI_CLI_SHA}
	docker tag ${GNMI_CLI_IMG}@${GNMI_CLI_SHA} ${GNMI_CLI_IMG}
	docker pull ${YANG_IMG}@${YANG_SHA}
	docker tag ${YANG_IMG}@${YANG_SHA} ${YANG_IMG}

# Pull all Docker images and build app to seed mvn repo inside container, i.e.
# download deps
pull-deps: _docker_pull_all _create_mvn_container _mvn_package

start:
	@mkdir -p tmp/onos
	docker-compose up -d

stop:
	docker-compose down

restart: reset start

onos-cli:
	$(info *** Connecting to the ONOS CLI... password: rocks)
	$(info *** Top exit press Ctrl-D)
	@ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -o LogLevel=ERROR -p 8101 onos@localhost

onos-log:
	docker-compose logs -f onos

onos-ui:
	open ${onos_url}/ui

mn-cli:
	$(info *** Attaching to Mininet CLI...)
	$(info *** To detach press Ctrl-D (Mininet will keep running))
	-@docker attach --detach-keys "ctrl-d" $(shell docker-compose ps -q mininet) || echo "*** Detached from Mininet CLI"

mn-log:
	docker logs -f mininet

netcfg:
	$(info *** Pushing netcfg.json to ONOS...)
	${onos_curl} -X POST -H 'Content-Type:application/json' \
		${onos_url}/v1/network/configuration -d@./mininet/netcfg.json
	@echo

reset: stop
	-rm -rf ./tmp

clean:
	-rm -rf p4src/build
	-rm -rf app/target
	-rm -rf app/src/main/resources/bmv2.json
	-rm -rf app/src/main/resources/p4info.txt

deep-clean: clean
	-docker container rm ${app_build_container_name}

p4-build-single: p4src/v1model/${P4_FILE}.p4
	$(info *** Building P4 program...)
	@rm -r p4src/v1model/${P4_FILE}
	@mkdir -p p4src/v1model/${P4_FILE}
	docker run --rm -v ${curr_dir}:/workdir -w /workdir ${P4C_IMG} \
		p4c-bm2-ss --arch v1model -o p4src/v1model/${P4_FILE}/bmv2.json \
		--p4runtime-files p4src/v1model/${P4_FILE}/p4info.txt --Wdisable=unsupported \
		p4src/v1model/${P4_FILE}.p4
	@echo "*** P4 program compiled successfully! Output files are in p4src/v1model/${P4_FILE}"

p4-build-all:
	$(MAKE) p4-build-single P4_FILE=bmv2_IP
	$(MAKE) p4-build-single P4_FILE=bmv2_ID
	$(MAKE) p4-build-single P4_FILE=bmv2_GEO
	$(MAKE) p4-build-single P4_FILE=bmv2_MF
	$(MAKE) p4-build-single P4_FILE=bmv2_NDN
  # $(MAKE) p4-build-single P4_FILE=bmv2_IP_ID
	$(MAKE) p4-build-single P4_FILE=bmv2_IP_GEO
	$(MAKE) p4-build-single P4_FILE=bmv2_IP_MF
	$(MAKE) p4-build-single P4_FILE=bmv2_IP_NDN
	$(MAKE) p4-build-single P4_FILE=bmv2_ID_GEO
	$(MAKE) p4-build-single P4_FILE=bmv2_ID_MF
	$(MAKE) p4-build-single P4_FILE=bmv2_ID_NDN
	$(MAKE) p4-build-single P4_FILE=bmv2_GEO_MF
	$(MAKE) p4-build-single P4_FILE=bmv2_GEO_NDN
	$(MAKE) p4-build-single P4_FILE=bmv2_MF_NDN
	$(MAKE) p4-build-single P4_FILE=bmv2_IP_ID_GEO
	$(MAKE) p4-build-single P4_FILE=bmv2_IP_ID_MF
	$(MAKE) p4-build-single P4_FILE=bmv2_IP_ID_NDN
	$(MAKE) p4-build-single P4_FILE=bmv2_IP_GEO_MF
	$(MAKE) p4-build-single P4_FILE=bmv2_IP_GEO_NDN
	$(MAKE) p4-build-single P4_FILE=bmv2_IP_MF_NDN
	$(MAKE) p4-build-single P4_FILE=bmv2_ID_GEO_MF
	$(MAKE) p4-build-single P4_FILE=bmv2_ID_GEO_NDN
	$(MAKE) p4-build-single P4_FILE=bmv2_ID_MF_NDN
	$(MAKE) p4-build-single P4_FILE=bmv2_GEO_MF_NDN
	$(MAKE) p4-build-single P4_FILE=bmv2_IP_ID_GEO_MF
	$(MAKE) p4-build-single P4_FILE=bmv2_IP_ID_GEO_NDN
	$(MAKE) p4-build-single P4_FILE=bmv2_IP_ID_MF_NDN
	$(MAKE) p4-build-single P4_FILE=bmv2_IP_GEO_MF_NDN
	$(MAKE) p4-build-single P4_FILE=bmv2_ID_GEO_MF_NDN
	$(MAKE) p4-build-single P4_FILE=bmv2_IP_ID_GEO_MF_NDN

p4-test:
	@cd ptf && ./run_tests $(TEST)

# Create container once, use it many times to preserve mvn repo cache.
_create_mvn_container:
	@if ! docker container ls -a --format '{{.Names}}' | grep -q ${app_build_container_name} ; then \
		docker create -v ${curr_dir}/app:/mvn-src -w /mvn-src --name ${app_build_container_name} ${MAVEN_IMG} mvn clean package; \
	fi

_copy_p4c_out:
	$(info *** Copying p4c outputs to app resources...)
	@mkdir -p app/src/main/resources
	cp -f p4src/build/p4info.txt app/src/main/resources/
	cp -f p4src/build/bmv2.json app/src/main/resources/

_mvn_package:
	$(info *** Building ONOS app...)
	@mkdir -p app/target
	@docker start -a -i ${app_build_container_name}

app-build: p4-build _copy_p4c_out _create_mvn_container _mvn_package
	$(info *** ONOS app .oar package created succesfully)
	@ls -1 app/target/*.oar

app-install:
	$(info *** Installing and activating app in ONOS...)
	${onos_curl} -X POST -HContent-Type:application/octet-stream \
		'${onos_url}/v1/applications?activate=true' \
		--data-binary @app/target/ngsdn-tutorial-1.0-SNAPSHOT.oar
	@echo

app-uninstall:
	$(info *** Uninstalling app from ONOS (if present)...)
	-${onos_curl} -X DELETE ${onos_url}/v1/applications/${app_name}
	@echo

app-reload: app-uninstall app-install

mn-single:
	docker run --privileged --rm -it -v /tmp/mn-stratum:/tmp -p 50001:50001 ${MN_STRATUM_IMG}

yang-tools:
	docker run --rm -it -v ${curr_dir}/yang/demo-port.yang:/models/demo-port.yang ${YANG_IMG}

solution-apply:
	cp -f app/src/main/java/org/onosproject/ngsdn/tutorial/pipeconf/InterpreterImpl.java app/src/main/java/org/onosproject/ngsdn/tutorial/pipeconf/InterpreterImpl.java.bak
	cp -f solution/exercise3/InterpreterImpl.java app/src/main/java/org/onosproject/ngsdn/tutorial/pipeconf/InterpreterImpl.java
	cp -f p4src/main.p4 p4src/main.p4.bak
	cp -f solution/exercise4/main.p4 p4src/main.p4
	cp -f ptf/tests/ndp.py ptf/tests/ndp.py.bak
	cp -f solution/exercise4/ndp.py ptf/tests/ndp.py
	cp -f app/src/main/java/org/onosproject/ngsdn/tutorial/NdpReplyComponent.java app/src/main/java/org/onosproject/ngsdn/tutorial/NdpReplyComponent.java.bak
	cp -f solution/exercise4/NdpReplyComponent.java app/src/main/java/org/onosproject/ngsdn/tutorial/NdpReplyComponent.java

solution-revert:
	-rm -f app/src/main/java/org/onosproject/ngsdn/tutorial/pipeconf/InterpreterImpl.java
	-mv app/src/main/java/org/onosproject/ngsdn/tutorial/pipeconf/InterpreterImpl.java.bak app/src/main/java/org/onosproject/ngsdn/tutorial/pipeconf/InterpreterImpl.java
	-rm -f p4src/main.p4
	-mv p4src/main.p4.bak p4src/main.p4
	-rm -f ptf/tests/ndp.py
	-mv ptf/tests/ndp.py.bak ptf/tests/ndp.py
	-rm -f app/src/main/java/org/onosproject/ngsdn/tutorial/NdpReplyComponent.java
	-mv app/src/main/java/org/onosproject/ngsdn/tutorial/NdpReplyComponent.java.bak app/src/main/java/org/onosproject/ngsdn/tutorial/NdpReplyComponent.java

check-solution:
	make reset
	make solution-apply
	make start
	make p4-build
	make p4-test
	make app-build
	sleep 30
	make app-reload
	sleep 10
	make netcfg
	sleep 10
	# The first ping might fail because of a known race condition in the
	# L2BridgingComponenet. Ping all hosts.
	-util/mn-cmd h1a ping -c 1 2001:1:1::b
	util/mn-cmd h1a ping -c 1 2001:1:1::b
	-util/mn-cmd h1b ping -c 1 2001:1:1::c
	util/mn-cmd h1b ping -c 1 2001:1:1::c
	-util/mn-cmd h2 ping -c 1 2001:1:1::b
	util/mn-cmd h2 ping -c 1 2001:1:1::b
	util/mn-cmd h2 ping -c 1 2001:1:1::a
	util/mn-cmd h2 ping -c 1 2001:1:1::c
	-util/mn-cmd h3 ping -c 1 2001:1:2::1
	util/mn-cmd h3 ping -c 1 2001:1:2::1
	util/mn-cmd h3 ping -c 1 2001:1:1::a
	util/mn-cmd h3 ping -c 1 2001:1:1::b
	util/mn-cmd h3 ping -c 1 2001:1:1::c
	-util/mn-cmd h4 ping -c 1 2001:1:2::1
	util/mn-cmd h4 ping -c 1 2001:1:2::1
	util/mn-cmd h4 ping -c 1 2001:1:1::a
	util/mn-cmd h4 ping -c 1 2001:1:1::b
	util/mn-cmd h4 ping -c 1 2001:1:1::c
	make stop
	make solution-revert
