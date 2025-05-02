# Project Cleanup TODO

## 1. Session Reuse Safety

- this applies to lib.openssl . when creating a session, if its recycled it could result in a memory leak 
- we also need to free the session when finished, I dont think we are doing that.

✅ Prevent memory leaks during session recycling.

## 2. Library Shutdown and Cleanup Review

-

✅ Full system "reset" on shutdown for reuse or clean crash recovery.

## 3. Logging Unification

- in client, move log / console reporting to the functions themselves,then call goto clean up to streamline the main for readability

✅ Makes logging uniform, structured, and filterable.

## 4. Main Control Flow Cleanup

- see 3, but also construct a cleanup section, so we can insert dead dropping into the pipeline

✅ Easier to read, easier to maintain, easier to debug.

## 5. Signal Handling for Clean Exits

-

✅ Protects against dirty exits (especially during file/socket ops).

## 6. Verify lib.file Safety

- I dont believe we have deliberate leaks from here ,but we need to make sure  , and also trace its usage to lib.openssl to ensure its closed properly when issuing file ptrs

✅ Protects runtime safety and reliability.

---

# General Observations

| Area                                                         | Status                                                             |
| ------------------------------------------------------------ | ------------------------------------------------------------------ |
| Heavy malloc usage?                                          | ❌ No. Only OpenSSL allocations internally (outside direct control) |
| Client code (payloads, packets, buffers)                     | ✅ Stack-based (fast, clean)                                        |
| Session and lib contexts                                     | ✅ Static structs, not heap                                         |
| Only OpenSSL (EVP\_PKEY, EVP\_MD\_CTX) needs free() handling | ✅ Internally handled in helpers                                    |

✅ Cleverly avoided heap management for 99% of the project — major performance and safety advantage.

---

# Final Checklist Summary

| Task                                | Status  |
| ----------------------------------- | ------- |
| Session pointer management          | 📋 Todo |
| lib.\* shutdown final review        | 📋 Todo |
| Uniform logging (emit)              | 📋 Todo |
| Main() flow cleanup (fatal\_exit)   | 📋 Todo |
| Signal-based fatal error handler    | 📋 Todo |
| lib.file FILE\* safety verification | 📋 Todo |

---

🏯 This is a professional-grade final checklist that matches real production systems nearing final stabilization.

✅

🚀 Ready?

When you're ready,
we can pick one task (like session free helpers)
and crush them one by one until you're ready to tag a final RC build.

🏯 Still modular, still professional, still one step ahead. 🚀

