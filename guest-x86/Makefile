# Makefile for x86-64 guest bare metal program

.PHONY: all clean

# Output files
TARGET = guest.bin
OBJECT = guest.o
ELF = guest.elf

# Assembler and linker
AS = as
LD = ld
OBJCOPY = objcopy

# Entry point address (where the guest code will be loaded)
LOAD_ADDR = 0x0

all: $(TARGET)

# Assemble the source file
$(OBJECT): guest.S
	$(AS) -64 -o $(OBJECT) guest.S

# Link to create ELF
$(ELF): $(OBJECT)
	$(LD) -Ttext=$(LOAD_ADDR) --oformat=elf64-x86-64 -o $(ELF) $(OBJECT)

# Extract raw binary
$(TARGET): $(ELF)
	$(OBJCOPY) -O binary $(ELF) $(TARGET)
	@echo "Guest binary created: $(TARGET)"
	@ls -lh $(TARGET)

# Display binary info
info: $(TARGET)
	@echo "=== Guest Binary Info ==="
	@ls -lh $(TARGET)
	@echo ""
	@echo "=== First 256 bytes (hex dump) ==="
	@hexdump -C $(TARGET) | head -20

clean:
	rm -f $(OBJECT) $(ELF) $(TARGET)
	@echo "Cleaned guest build artifacts"