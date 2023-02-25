.PHONY: build run clean install uninstall

include openwrt.conf
export

build:
	./build.sh

run:
	./run.sh

clean:
	docker stop ${CONTAINER} || true
	docker rm ${CONTAINER} || true
	docker network rm ${LAN_NAME} ${WAN_NAME} || true

install:
	install -Dm644 openwrtmultiwan.service /usr/lib/systemd/system/openwrtmultiwan.service
	sed -i -E "s#(ExecStart=).*#\1`pwd`/run.sh#g" /usr/lib/systemd/system/openwrtmultiwan.service
	systemctl daemon-reload
	systemctl enable openwrtmultiwan.service
	systemctl start openwrtmultiwan.service
	@echo "OpenWrt service installed and will be started on next boot automatically."
	@echo "To view status, run 'systemctl status openwrtmultiwan.service'."

uninstall:
	systemctl stop openwrtmultiwan.service
	systemctl disable openwrtmultiwan.service
	rm /usr/lib/systemd/system/openwrtmultiwan.service
	systemctl daemon-reload