# Encrypted Database Demo & Benchmark

This project demonstrates a secure, homomorphically‐encrypted database system using:

- **Functional Encryption (FE)** with Paillier cryptosystem for aggregate queries (SUM, COUNT, AVG).
- **SimpleFHE** (a lightweight BFV‐style scheme) as a baseline FHE implementation.
- **Searchable Symmetric Encryption (SSE)** fallback for filtering (WHERE clauses) when FE cannot handle non‐aggregate queries.

It includes a Tkinter-based GUI, client and server microservices, a trusted authority (TA) for key management, and a benchmarking script to compare performance across FE, SSE and SimpleFHE.
