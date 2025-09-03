--TODO: Test how good this actually works. Replace existing random functions with this new implementation.
-- cr1n/sova
-- simple software based entropy
local ffi = require("ffi")

ffi.cdef[[
    typedef unsigned long DWORD;
    typedef void* HCRYPTPROV;
    typedef int BOOL;
    
    // CryptoAPI functions
    BOOL CryptAcquireContextA(HCRYPTPROV* phProv, const char* szContainer,
                             const char* szProvider, DWORD dwProvType, DWORD dwFlags);
    BOOL CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, unsigned char* pbBuffer);
    BOOL CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags);
    
    // System time functions
    unsigned long long GetTickCount64(void);
    int GetTickCount(void);
    
    // Additional Windows API for more entropy
    void GetSystemTimeAsFileTime(void* lpSystemTimeAsFileTime);
    unsigned long GetTickCount(void);
]]

local kernel32 = ffi.load("kernel32")
local advapi32 = ffi.load("advapi32")

local PROV_RSA_FULL = 1
local CRYPT_VERIFYCONTEXT = 0xF0000000

local function get_crypto_random_bytes(n)
    local prov = ffi.new("HCRYPTPROV[1]")
    
    -- Initializing the cryptographic provider
    local result = advapi32.CryptAcquireContextA(prov, nil, nil, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)
    if result == 0 then
        error("Failed to initialize cryptographic provider")
    end
    local buffer = ffi.new("unsigned char[?]", n)
    result = advapi32.CryptGenRandom(prov[0], n, buffer)
    if result == 0 then
        advapi32.CryptReleaseContext(prov[0], 0)
        error("Failed to generate random numbers")
    end
    
    advapi32.CryptReleaseContext(prov[0], 0)
    
    return ffi.string(buffer, n)
end

local function get_system_time_entropy()
    local filetime = ffi.new("unsigned char[8]")
    kernel32.GetSystemTimeAsFileTime(filetime)
    
    local time_value = 0
    for i = 0, 7 do
        time_value = bit32.bor(bit32.lshift(time_value, 8), filetime[i])
    end
    
    return time_value
end

-- Getting time from different timers
local function get_time_entropy()
    local t1 = tonumber(kernel32.GetTickCount64())
    local t2 = kernel32.GetTickCount()
    local t3 = get_system_time_entropy()
    
    return bit32.bxor(t1, bit32.lshift(t2, 13), bit32.lshift(t3, 7))
end

-- Combined function for getting entropy
local function get_combined_entropy()
    -- Getting cryptographically secure random bytes
    local crypto_bytes = get_crypto_random_bytes(8)

    -- Converting bytes to number
    local crypto_value = 0
    for i = 1, #crypto_bytes do
        local byte = string.byte(crypto_bytes, i)
        crypto_value = bit32.bor(bit32.lshift(crypto_value, 8), byte)
    end
    
    local time_entropy = get_time_entropy()
    
    local combined = bit32.bxor(crypto_value, time_entropy)
    
    combined = bit32.bxor(combined, bit32.rshift(combined, 16))
    combined = bit32.bxor(combined, bit32.lshift(combined, 11))
    combined = bit32.bxor(combined, bit32.rshift(combined, 23))

    return combined
end

function math.absolute_random(a, b)
    if a > b then a, b = b, a end -- swap if needed
    local range = b - a + 1
    if range <= 0 then return a end
    
    local entropy_value = get_combined_entropy()
    local random_value = entropy_value % range
    
    return a + random_value
end

function math.absolute_random_float()
    local bytes = get_crypto_random_bytes(4)
    local value = 0
    for i = 1, 4 do
        local byte = string.byte(bytes, i)
        value = bit32.bor(bit32.lshift(value, 8), byte)
    end
    return value / 0xFFFFFFFF
end

function math.absolute_random_array(count, a, b)
    local result = {}
    for i = 1, count do
        result[i] = math.absolute_random(a or 0, b or 100)
    end
    return result
end

function math.absolute_random_large()
    local bytes = get_crypto_random_bytes(8)
    local value = 0
    for i = 1, 8 do
        local byte = string.byte(bytes, i)
        value = bit32.bor(bit32.lshift(value, 8), byte)
    end
    return math.abs(value)
end