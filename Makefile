.PHONY: help up up-matrix test matrix detect verify-patch compare evidence clean

help:
	@echo "================================================================================"
	@echo "  HE THONG DIEU PHOI PHONG LAB CVE-2026-111497 (NODE2SHELL)"
	@echo "================================================================================"
	@echo "  make up            : Khoi chay toan bo Lab (WAF + 5 Node Versions + Falco + Dozzle)"
	@echo "  make up-matrix     : Chi khoi chay rieng 5 phien ban Node.js trong thu muc ./lab"
	@echo "  make test          : Chay bo 5 kich ban kiem thu (attacker/scripts/run_all_tests.py)"
	@echo "  make matrix        : Chay doi chung ma tran 5 phien ban Node.js (3020..3026)"
	@echo "  make detect        : Kiem chung he thong Phat hien Da tang (WAF, ExitCode, Falco)"
	@echo "  make verify-patch  : Chay kiem thu nghiem thu sau khi va (verify_remediation.py)"
	@echo "  make compare       : So sanh truc tiep A/B giua ban Loi (:3000) va ban Va (:3002)"
	@echo "  make evidence      : Tu dong thu thap Log, JSON Scorecard vao ./evidence"
	@echo "  make clean         : Tat va don dep toan bo Container Lab"
	@echo "================================================================================"

up:
	./start-lab.sh

up-matrix:
	docker compose -f lab/docker-compose.yml up -d --build

test:
	python3 attacker/scripts/run_all_tests.py -o evidence/test_scorecard.json

matrix:
	python3 lab/compare_versions_matrix.py -o evidence/version_matrix_report.json

detect:
	python3 detection/verify_detections.py

verify-patch:
	python3 remediation/tests/verify_remediation.py --waf-port 8080 --app-port 3002 -o evidence/remediation_verify.json

compare:
	python3 remediation/tests/compare_labs.py --vuln-port 3000 --patched-port 3002 -o evidence/ab_comparison_report.json

evidence:
	./scripts/collect_evidence.sh

clean:
	./cleanup-lab.sh
