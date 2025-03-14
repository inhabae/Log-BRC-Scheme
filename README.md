# Project Overview: Logarithmic-BRC Scheme Implementation

This project implements the Logarithmic-BRC (Log-BRC) scheme, a privacy-preserving method for range queries over encrypted data, as outlined in "Practical Private Range Search Revisited" by Demertzis et al. (2016). It enables efficient searches for records within a numerical range (e.g., ages 25–50) on a semi-honest cloud server without revealing sensitive data. The implementation is compared against PiBas, a baseline Searchable Symmetric Encryption (SSE) scheme that simulates range queries using point lookups.

The project, written in C++ with OpenSSL for cryptographic operations (HMAC-SHA256 and AES-256-CTR), evaluates both schemes across two key metrics: setup time (index construction) and search time (query execution). Log-BRC achieves a setup complexity of $O(n \log m)$ and a search complexity of $O(\log R + r)$, where $n$ is the number of data items, $m$ is the domain size (100 in this case), $R$ is the range size, and $r$ is the number of results. PiBas, in contrast, has a simpler $O(n)$ setup but a costlier $O(R \log n + r \log r)$ search time due to its linear iteration over range values and deduplication overhead.

Experiments conducted on an Apple M2 with 8 GB RAM test:
1. **Setup and Search vs. Input Size**: Varying $n$ from $2^1$ to $2^{20}$ with a fixed range [25, 50].
2. **Search vs. Range Size**: Varying $R$ from 1 to 100 at $n = 2^{20}$.

Results show Log-BRC outperforms PiBas by 5–10× in search time for small ranges (e.g., 186 ms vs. 1,850 ms at $n = 2^{20}$, $R = 26$), though its setup is slightly slower (8,508 ms vs. 8,218 ms). The project demonstrates a practical trade-off between setup cost and query efficiency, optimized for constrained hardware, with potential applications in secure databases like medical or financial systems.
