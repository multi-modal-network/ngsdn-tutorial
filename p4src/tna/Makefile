p4-build:
	${info *** Building pb.txt/.tofino for ${P4_FILE} ...}
	bf-p4c --std p4-16 --arch tna --p4runtime-files ${P4_FILE}.pb.txt --p4runtime-force-std-externs --auto-init-metadata ${P4_FILE}.p4
	~/p4runtime-shell/config_builders/tofino.py --ctx-json ${P4_FILE}.tofino/pipe/context.json --tofino-bin ${P4_FILE}.tofino/pipe/tofino.bin -p ${P4_FILE} -o ${P4_FILE}.bin

p4-pos:
	$(info *** Building P4 program ${P4_FILE}...)
	mv ${P4_FILE}.tofino ${P4_FILE}/${P4_FILE}.tofino
	rm -r ${P4_FILE}/pipe

p4-all:
	${info *** Moving ...}
	make p4-pos P4_FILE="tofino_IP"
	make p4-pos P4_FILE="tofino_ID"
	make p4-pos P4_FILE="tofino_GEO"
	make p4-pos P4_FILE="tofino_MF"
	make p4-pos P4_FILE="tofino_NDN"
	make p4-pos P4_FILE="tofino_IP_ID"
	make p4-pos P4_FILE="tofino_IP_GEO"
	make p4-pos P4_FILE="tofino_IP_MF"
	make p4-pos P4_FILE="tofino_IP_NDN"
	make p4-pos P4_FILE="tofino_ID_GEO"
	make p4-pos P4_FILE="tofino_ID_MF"
	make p4-pos P4_FILE="tofino_ID_NDN"
	make p4-pos P4_FILE="tofino_GEO_MF"
	make p4-pos P4_FILE="tofino_GEO_NDN"
	make p4-pos P4_FILE="tofino_MF_NDN"
	make p4-pos P4_FILE="tofino_IP_ID_GEO"
	make p4-pos P4_FILE="tofino_IP_ID_MF"
	make p4-pos P4_FILE="tofino_IP_ID_NDN"
	make p4-pos P4_FILE="tofino_IP_GEO_MF"
	make p4-pos P4_FILE="tofino_IP_GEO_NDN"
	make p4-pos P4_FILE="tofino_IP_MF_NDN"
	make p4-pos P4_FILE="tofino_ID_GEO_MF"
	make p4-pos P4_FILE="tofino_ID_GEO_NDN"
	make p4-pos P4_FILE="tofino_ID_MF_NDN"
	make p4-pos P4_FILE="tofino_GEO_MF_NDN"
	make p4-pos P4_FILE="tofino_IP_ID_GEO_MF"
	make p4-pos P4_FILE="tofino_IP_ID_GEO_NDN"
	make p4-pos P4_FILE="tofino_IP_ID_MF_NDN"
	make p4-pos P4_FILE="tofino_IP_GEO_MF_NDN"
	make p4-pos P4_FILE="tofino_ID_GEO_MF_NDN"
	make p4-pos P4_FILE="tofino_IP_ID_GEO_MF_NDN"

p4-tna-build:
	${info *** Building ...}
	make p4-build P4_FILE="tofino_IP"
	make p4-build P4_FILE="tofino_ID"
	make p4-build P4_FILE="tofino_GEO"
	make p4-build P4_FILE="tofino_MF"
	make p4-build P4_FILE="tofino_NDN"
	make p4-build P4_FILE="tofino_IP_ID"
	make p4-build P4_FILE="tofino_IP_GEO"
	make p4-build P4_FILE="tofino_IP_MF"
	make p4-build P4_FILE="tofino_IP_NDN"
	make p4-build P4_FILE="tofino_ID_GEO"
	make p4-build P4_FILE="tofino_ID_MF"
	make p4-build P4_FILE="tofino_ID_NDN"
	make p4-build P4_FILE="tofino_GEO_MF"
	make p4-build P4_FILE="tofino_GEO_NDN"
	make p4-build P4_FILE="tofino_MF_NDN"
	make p4-build P4_FILE="tofino_IP_ID_GEO"
	make p4-build P4_FILE="tofino_IP_ID_MF"
	make p4-build P4_FILE="tofino_IP_ID_NDN"
	make p4-build P4_FILE="tofino_IP_GEO_MF"
	make p4-build P4_FILE="tofino_IP_GEO_NDN"
	make p4-build P4_FILE="tofino_IP_MF_NDN"
	make p4-build P4_FILE="tofino_ID_GEO_MF"
	make p4-build P4_FILE="tofino_ID_GEO_NDN"
	make p4-build P4_FILE="tofino_ID_MF_NDN"
	make p4-build P4_FILE="tofino_GEO_MF_NDN"
	make p4-build P4_FILE="tofino_IP_ID_GEO_MF"
	make p4-build P4_FILE="tofino_IP_ID_GEO_NDN"
	make p4-build P4_FILE="tofino_IP_ID_MF_NDN"
	make p4-build P4_FILE="tofino_IP_GEO_MF_NDN"
	make p4-build P4_FILE="tofino_ID_GEO_MF_NDN"
	make p4-build P4_FILE="tofino_IP_ID_GEO_MF_NDN"