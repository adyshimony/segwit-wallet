// File: secure_memory.hpp
// Brief: Secure memory handling for sensitive cryptographic data
// 
// This class provides memory protection for sensitive data like private keys:
// - Prevents memory from being swapped to disk
// - Zeroes memory on destruction
// - Provides controlled access to the underlying data

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace wallet {

class SecureMemory {
private:
    uint8_t* data_;
    size_t size_;
    
public:
    // Constructor that accepts sensitive data
    SecureMemory(const uint8_t* input, size_t length) {
        size_ = length;
        data_ = new uint8_t[size_];
        
        // Copy the data
        std::memcpy(data_, input, size_);
        
        // Lock the memory to prevent swapping to disk
        #ifdef _WIN32
        VirtualLock(data_, size_);
        #else
        if (mlock(data_, size_) != 0) {
            // Handle error if mlock fails, but continue
            // This might happen if the process doesn't have the right permissions
        }
        #endif
    }
    
    // Destructor to clean up
    ~SecureMemory() {
        if (data_) {
            // Zero the memory before freeing
            std::memset(data_, 0, size_);
            
            // Unlock the memory
            #ifdef _WIN32
            VirtualUnlock(data_, size_);
            #else
            munlock(data_, size_);
            #endif
            
            delete[] data_;
            data_ = nullptr;
            size_ = 0;
        }
    }
    
    // Prevent copying
    SecureMemory(const SecureMemory&) = delete;
    SecureMemory& operator=(const SecureMemory&) = delete;
    
    // Allow moving
    SecureMemory(SecureMemory&& other) noexcept : data_(other.data_), size_(other.size_) {
        other.data_ = nullptr;
        other.size_ = 0;
    }
    
    SecureMemory& operator=(SecureMemory&& other) noexcept {
        if (this != &other) {
            // Clean up existing data
            if (data_) {
                std::memset(data_, 0, size_);
                #ifdef _WIN32
                VirtualUnlock(data_, size_);
                #else
                munlock(data_, size_);
                #endif
                delete[] data_;
            }
            
            // Move data from other
            data_ = other.data_;
            size_ = other.size_;
            
            // Reset other
            other.data_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }
    
    // Controlled access to data
    const uint8_t* data() const { return data_; }
    size_t size() const { return size_; }
    
    // Helper method to check if empty
    bool isEmpty() const { return size_ == 0 || data_ == nullptr; }
};

} // namespace wallet 