CFLAGS += -g
LDFLAGS += -g

kvm_test: kvm_test.c

clean:
	rm kvm_test
