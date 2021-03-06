#define _GNU_SOURCE
#include <stdlib.h>

/* spinlock  */
#include <threads.h>

typedef mtx_t spinlock_t;
#define spin_lock(mm)                                                          \
    ({                                                                         \
        mtx_lock(&mm->page_table_lock);                                        \
        &mm->page_table_lock;                                                  \
    })
#define spin_unlock(ptl) mtx_unlock(ptl)

/**
 * page marco and struct page define
 */
#define PAGE_SHIFT 12
#define PAGE_SIZE (_AC(1, UL) << PAGE_SHIFT)
#define PAGE_MASK (~((1 << PAGE_SHIFT) - 1))

#define _AC(X, Y) X
#define _UL(x) (_AC(x, UL))
#define UL(x) (_UL(x))

#define ALIGH(x, mask) (((x) + (mask)) & ~(mask))
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)

struct page {
    char buf[8];
};

/**
 * 3 level page table marco
 *
 *          pgd -> pmd -> pte -> page frame
 *
 * It is 4 pgd in mm_stuct pointed by mm_struct->pgd,
 * The pmd amd pte size are 4096, and each pte will
 * point to the pgtable type page frame which size also
 * 4096 bytes.
 * Different from the pte point to the physical page in
 * linux kerenl, the page frame here is the 512 number of
 * struct page.
 */

#include <stdint.h>

typedef uint64_t pteval_t;
typedef uint64_t pmdval_t;
typedef uint64_t pgdval_t;

/* C type-checking */
typedef struct {
    pteval_t pte;
} pte_t;
typedef struct {
    pmdval_t pmd;
} pmd_t;
typedef struct {
    pgdval_t pgd;
} pgd_t;
typedef struct {
    pteval_t pgprot;
} pgprot_t;

#define pte_val(x) ((x).pte)
#define pmd_val(x) ((x).pmd)
#define pgd_val(x) ((x).pgd)
#define pgprot_val(x) ((x).pgprot)

#define __pte(x) ((pte_t){ (x) })
#define __pmd(x) ((pmd_t){ (x) })
#define __pgd(x) ((pgd_t){ (x) })
#define __pgprot(x) ((pgprot_t){ (x) })

#define pmd_none(pmd) (!pmd_val(pmd))
#define pgd_none(pgd) (!pgd_val(pgd))
#define pgd_present(pgd) (pgd_val(pgd))

#define PMD_SHIFT 21

#define PMD_SIZE (1UL << PMD_SHIFT)
#define PMD_MASK (~((1 << PMD_SHIFT) - 1))
#define PGDIR_SIZE (1UL << PGDIR_SHIFT)
#define PGDIR_MASK (~((1 << PGDIR_SHIFT) - 1))

#define PGDIR_SHIFT 30

#define PTRS_PER_PTE 512
#define PTRS_PER_PMD 512
#define PTRS_PER_PGD 4

#define pgd_index(a) (((a) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pmd_index(a) (((a) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pte_index(a) ((a >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))

typedef struct page *pgtable_t; /* page frame */

pgtable_t pgtable_new(void)
{
    pgtable_t new = (pgtable_t)malloc(sizeof(struct page) * 512);
    if (!new)
        return NULL;
    return new;
}

#include <stdatomic.h>

#define u64 uint64_t
#define atomic_u64 atomic_uint_fast64_t

struct mm_struct {
    pgd_t *pgd;
    spinlock_t page_table_lock;
    atomic_u64 pgtables_bytes;
};

/**
 * page table allocate function
 */

#include <string.h>
#include <sys/mman.h>

int __pte_alloc(struct mm_struct *mm, pmd_t *pmd)
{
    pte_t *new = (pte_t *)mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    spinlock_t *ptl;
    if (!new)
        return 1;

    memset(new, 0, 4096);

    ptl = spin_lock(mm);
    if (pmd_none(*pmd)) {
        atomic_fetch_add(&mm->pgtables_bytes, 512 * sizeof(pte_t));

        pmdval_t pmdval = (pmdval_t) new;
        pmd[0] = __pmd(pmdval);
    }
    else {
        munmap(new, 4096);
    }
    spin_unlock(ptl);
    return 0;
}

static inline pte_t *pte_offset(pmd_t *pmd, u64 addr)
{
    pmdval_t pmdval = pmd_val(pmd[0]);
    return (pte_t *)pmdval + pte_index(addr);
}

static inline pte_t *pte_alloc(struct mm_struct *mm, pmd_t *pmd, u64 address)
{
    return ((pmd_none(*(pmd)) && __pte_alloc(mm, pmd)) ?
                    NULL :
                    pte_offset(pmd, address));
}

int __pmd_alloc(struct mm_struct *mm, pgd_t *pgd)
{
    spinlock_t *ptl;
    pmd_t *new = (pmd_t *)mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (new == MAP_FAILED)
        return 1;

    memset(new, 0, 4096);

    ptl = spin_lock(mm);
    if (!pgd_present(*pgd)) {
        atomic_fetch_add(&mm->pgtables_bytes, 512 * sizeof(pmd_t));

        pgdval_t pgdval = (pgdval_t) new;
        pgd[0] = __pgd(pgdval);
    } else {
        munmap(new, 4096);
    }
    spin_unlock(ptl);
    return 0;
}

static inline pmd_t *pmd_offset(pgd_t *pgd, u64 addr)
{
    pgdval_t pgdval = pgd_val(pgd[0]);
    return (pmd_t *)pgdval + pmd_index(addr);
}

static inline pmd_t *pmd_alloc(struct mm_struct *mm, pgd_t *pgd, u64 address)
{
    return ((pgd_none(*(pgd)) && __pmd_alloc(mm, pgd)) ?
                    NULL :
                    pmd_offset(pgd, address));
}

int pgd_alloc(struct mm_struct *mm)
{
    pgd_t *new_pgd;

    new_pgd = (pgd_t *)malloc(sizeof(pgd_t) * 4);
    if (!new_pgd)
        goto no_pgd;

    memset(new_pgd, 0, sizeof(pgd_t) * 4);

    mm->pgd = new_pgd;
    atomic_fetch_add(&mm->pgtables_bytes, 4 * sizeof(pgd_t));
    return 1;

no_pgd:
    return 0;
}

static inline pgd_t *pgd_offset(pgd_t *pgd, u64 address)
{
    return (pgd + pgd_index(address));
};

pmd_t *walk_to_pmd(struct mm_struct *mm, u64 addr)
{
    pgd_t *pgd;
    pmd_t *pmd;
    pgd = pgd_offset(mm->pgd, addr);
    pmd = pmd_alloc(mm, pgd, addr);
    if (!pmd)
        return NULL;
    return pmd;
}

/* old version */
int insert_page(struct mm_struct *mm, struct page *page, u64 addr)
{
    pte_t *pte;
    spinlock_t *ptl;

    pmd_t *pmd = walk_to_pmd(mm, addr);
    if (!pmd)
        return -1;
    pte = pte_alloc(mm, pmd, addr);
    if (!pte)
        return -2;
    ptl = spin_lock(mm);
    pteval_t pteval = pte_val(pte[0]);
    pgtable_t table = (pgtable_t)pteval;
    if (!table) {
        table = pgtable_new();
        if (!table) {
            spin_unlock(ptl);
            return -3;
        }
        pteval = (pteval_t)table;
        pte[0] = __pte(pteval);
    }
    // table[addr & ~PAGE_MASK] = *page;
    memcpy(table[addr & ~PAGE_MASK].buf, page->buf, 8);
    spin_unlock(ptl);
    return 0;
}

/**
 * test function start here :
 * - test_insert_page
 */
#include <stdio.h>


#define mm_init()                                                              \
    ({                                                                         \
        struct mm_struct __mm = {                                              \
            .pgd = NULL,                                                       \
        };                                                                     \
        mtx_init(&__mm.page_table_lock, mtx_plain);                            \
        atomic_store(&__mm.pgtables_bytes, 0);                                 \
        __mm;                                                                  \
    })

void test_insert_page_check(struct mm_struct *mm, u64 va, u64 pgdi, u64 pmdi,
                            u64 ptei, u64 offset)
{
    pgdval_t pgdval = pgd_val(mm->pgd[pgdi]);
    pmd_t *pmd = (pmd_t *)pgdval;
    printf("[3] pmd start %p\n", pmd);
    pmdval_t pmdval = pmd_val(pmd[pmdi]);
    pte_t *pte = (pte_t *)pmdval;
	printf("[4] pte start %p\n", pte);
    pteval_t pteval = pte_val(pte[ptei]);
	printf("[5] pte offset %p\n", (void *)pteval);    
	pgtable_t table = (pgtable_t)pteval;
	printf("out %s\n", table[offset].buf);
}

void test_insert_page(void)
{
    u64 pgdi = 3;
    u64 pmdi = 12;
    u64 ptei = 2;
    u64 offset = 8;
    struct page pg;
    struct mm_struct mm = mm_init();
    pgd_alloc(&mm);

    for (int i = 0; i < 10; i++) {
        printf("----------------test %d------------------\n", i);
        pgdi = i % 4;
        pmdi = i;
        ptei = i;
        offset = i;
        u64 va = 0;

        char buf[8];
        sprintf(buf, "pg %d", i);
        buf[7] = '\0';
        strncpy(pg.buf, buf, 8);

        // pgd set
        va |= (pgdi << PGDIR_SHIFT);
        // pmd set
        va |= (pmdi << PMD_SHIFT);
        // pte set
        va |= (ptei << PAGE_SHIFT);
        // offset set
        va = va | offset;
        printf("[0] va = %p\n", (void *)va);
        printf("[pgd index] set %lu, get %lu\n", pgdi, pgd_index(va));
        printf("[pmd index] set %lu, get %lu\n", pmdi, pmd_index(va));
        printf("[pte index] set %lu, get %lu\n", ptei, pte_index(va));
        printf("[offset index] set %lu, get %lu\n", offset, va & ~PAGE_MASK);

        printf("[1] insert_page start\n");
        insert_page(&mm, &pg, va);
        printf("[2] insert_page finish\n");

        test_insert_page_check(&mm, va, pgdi, pmdi, ptei, offset);
    }
}

int main(void)
{
    test_insert_page();
    return 0;
}
