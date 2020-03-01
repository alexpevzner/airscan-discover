all:
	-gotags -R . > tags
	go build -ldflags "-s -w"

clean:
	rm -d tags airscan-discover
