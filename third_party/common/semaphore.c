#include "semaphore.h"

void sem_dec(uint32_t* semaphore) {
#if AARCH == 64
    for (;;) {
      uint32_t value = __atomic_load_n(semaphore, __ATOMIC_ACQUIRE);
      if (value == 0) {
        __asm__ volatile ("wfe" ::: "memory");
        continue;
      }

      if (__atomic_compare_exchange_n(semaphore, &value, value - 1, 0,
                                      __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        return;
      }
    }
#else
    asm volatile (
      "1:  LDREX    r1, [r0]\n"
      "    CMP	    r1, #0\n"
      "    BEQ     2f             \n"
      "    SUB     r1, #1        \n"
      "    STREX   r2, r1, [r0]  \n"
      "    CMP     r2, #0        \n"
      "    BNE     1b            \n"
      "    DMB                   \n"
      "    B       3f\n"
      "2: \n" 
      "    wfe \n"
      "    B       1b\n"
      "3:\n"
    );
#endif
}

void sem_inc(uint32_t* semaphore) {
#if AARCH == 64
    uint32_t old = __atomic_fetch_add(semaphore, 1, __ATOMIC_ACQ_REL);
    if (old == 0) {
      __asm__ volatile ("dmb ishst" ::: "memory");
      __asm__ volatile ("sev" ::: "memory");
    }
#else
    asm volatile (
      "1:   LDREX   r1, [r0]\n"
      "     ADD     r1, #1\n"
      "     STREX   r2, r1, [r0]\n"
      "     CMP     r2, #0\n"
      "     BNE     1b\n"
      "     CMP     r0, #1\n"
      "     DMB\n"
      "     BGE     2f\n"
      "     B       3f\n"
      "2:\n"
      "     DSB\n"
      "     SEV\n"
      "3:\n"
    );
#endif
}
