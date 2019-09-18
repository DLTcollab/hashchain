BIN = hashchain
CFLAGS = -Os

all: $(BIN)


$(BIN): $(BIN).c
	$(CC) -o $@ $< -lcrypto

gen: $(BIN)
	./$< create sha256 10 `base64 /dev/urandom | head -c 32` > chains

clean:
	$(RM) $(BIN)

distclean: clean
	$(RM) chains
