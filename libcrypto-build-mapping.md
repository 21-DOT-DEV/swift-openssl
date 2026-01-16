# libcrypto Build Mapping

**Configure Options:** `./Configure darwin64-arm64-cc no-asm no-shared no-apps no-docs no-tests`

This document maps OpenSSL's `build.info` files to `subtree.yaml` extraction rules.

---

## Summary

| Category | Subdirectories |
|----------|----------------|
| **Core** | `crypto/` (root), `buffer`, `stack`, `lhash`, `hashtable`, `err`, `objects` |
| **Crypto Primitives** | `aes`, `des`, `chacha`, `poly1305`, `modes` |
| **Hash Functions** | `sha`, `md5`, `ripemd`, `hmac`, `cmac`, `siphash` |
| **Asymmetric** | `bn`, `rsa`, `dsa`, `dh`, `ec`, `sm2` |
| **Encoding/Formats** | `asn1`, `pem`, `x509`, `pkcs7`, `pkcs12`, `cms` |
| **Infrastructure** | `bio`, `evp`, `rand`, `conf`, `engine`, `dso`, `property`, `store`, `encode_decode` |
| **Protocols** | `ocsp`, `ts`, `ct`, `cmp`, `crmf`, `ess`, `srp`, `http`, `hpke` |
| **Threading/Async** | `thread`, `async`, `ffc` |
| **Disabled (no-asm)** | Assembly files (*.S, *.s) |
| **Excluded (legacy)** | `md2`, `md4`, `mdc2`, `whrlpool`, `bf`, `cast`, `idea`, `rc2`, `rc4`, `rc5`, `seed`, `camellia`, `aria`, `sm3`, `sm4` |

---

## Detailed Mapping

### 1. Core (`crypto/` root)

**From:** `Vendor/openssl/crypto/build.info` lines 91-110

**Sources (no-asm build):**
```
# CPUID (no-asm uses mem_clr.c)
mem_clr.c cpuid.c ctype.c

# Core
provider_core.c provider_predefined.c core_fetch.c core_algorithm.c 
core_namemap.c self_test_core.c provider_conf.c indicator_core.c

# Utilities
cryptlib.c params.c params_from_text.c bsearch.c ex_data.c o_str.c
threads_pthread.c threads_win.c threads_none.c threads_common.c
initthread.c context.c sparse_array.c asn1_dsa.c packet.c
param_build.c param_build_set.c der_writer.c threads_lib.c
params_dup.c time.c array_alloc.c deterministic_nonce.c
mem.c mem_sec.c comp_methods.c cversion.c info.c cpt_err.c 
ebcdic.c uid.c o_time.c o_dir.c o_fopen.c getenv.c o_init.c 
init.c trace.c provider.c provider_child.c punycode.c passphrase.c 
sleep.c quic_vlint.c defaults.c ssl_err.c
```

**Exclusions:**
- `dllmain.c` (Windows)
- `uplink*.c/S` (uplink disabled)
- All `*cpuid.S/s` assembly files

---

### 2. Objects (`crypto/objects/`)

**Sources:**
```
o_names.c obj_dat.c obj_lib.c obj_err.c obj_xref.c
```

---

### 3. Buffer (`crypto/buffer/`)

**Sources:**
```
buffer.c buf_err.c
```

---

### 4. BIO (`crypto/bio/`)

**Sources:**
```
# Base
bio_lib.c bio_cb.c bio_err.c bio_print.c bio_dump.c bio_addr.c
bio_sock.c bio_sock2.c bio_meth.c ossl_core_bio.c

# Source/sink
bss_null.c bss_mem.c bss_bio.c bss_fd.c bss_file.c
bss_sock.c bss_conn.c bss_acpt.c bss_dgram.c
bss_log.c bss_core.c bss_dgram_pair.c

# Filters
bf_null.c bf_buff.c bf_lbuf.c bf_nbio.c bf_prefix.c bf_readbuff.c
```

---

### 5. Stack (`crypto/stack/`)

**Sources:**
```
stack.c
```

---

### 6. LHash (`crypto/lhash/`)

**Sources:**
```
lhash.c lh_stats.c
```

---

### 7. HashTable (`crypto/hashtable/`)

**Sources:**
```
hashtable.c hashfunc.c
```

---

### 8. Rand (`crypto/rand/`)

**Sources:**
```
rand_lib.c randfile.c rand_err.c rand_deprecated.c prov_seed.c 
rand_uniform.c rand_pool.c
```

**Conditional (disabled by default):**
- `rand_egd.c` (egd disabled)
- `rand_meth.c` (deprecated-3.0)

---

### 9. EVP (`crypto/evp/`)

**Sources:**
```
digest.c evp_enc.c evp_lib.c evp_fetch.c evp_utils.c
mac_lib.c mac_meth.c keymgmt_meth.c keymgmt_lib.c kdf_lib.c kdf_meth.c
skeymgmt_meth.c pmeth_lib.c signature.c p_lib.c s_lib.c pmeth_gn.c 
exchange.c evp_rand.c asymcipher.c kem.c dh_support.c ec_support.c 
pmeth_check.c evp_pkey_type.c encode.c evp_key.c evp_cnf.c
e_des.c e_bf.c e_idea.c e_des3.c e_rc4.c e_aes.c names.c e_aria.c 
e_sm4.c e_xcbc_d.c e_rc2.c e_cast.c e_rc5.c m_null.c
p_seal.c p_sign.c p_verify.c p_legacy.c
bio_md.c bio_b64.c bio_enc.c evp_err.c e_null.c
c_allc.c c_alld.c bio_ok.c
evp_pkey.c evp_pbe.c p5_crpt.c p5_crpt2.c pbe_scrypt.c
e_aes_cbc_hmac_sha1.c e_aes_cbc_hmac_sha256.c e_rc4_hmac_md5.c
e_chacha20_poly1305.c legacy_sha.c ctrl_params_translate.c
cmeth_lib.c m_sigver.c dh_ctrl.c dsa_ctrl.c ec_ctrl.c
p_enc.c p_dec.c (deprecated-3.0)
e_old.c (deprecated-0.9.8)
p_open.c (rsa enabled)
legacy_md5.c legacy_md5_sha1.c (md5 enabled)
legacy_ripemd.c (rmd160 enabled)
```

---

### 10. ASN1 (`crypto/asn1/`)

**Sources:**
```
a_object.c a_bitstr.c a_utctm.c a_gentm.c a_time.c a_int.c a_octet.c
a_print.c a_type.c a_dup.c a_d2i_fp.c a_i2d_fp.c
a_utf8.c a_sign.c a_digest.c a_verify.c a_mbstr.c a_strex.c
x_algor.c x_val.c x_sig.c x_bignum.c x_int64.c x_info.c x_spki.c nsseq.c
d2i_pu.c d2i_pr.c i2d_evp.c t_pkey.c t_spki.c t_bitst.c
tasn_new.c tasn_fre.c tasn_enc.c tasn_dec.c tasn_utl.c tasn_typ.c
tasn_prn.c tasn_scn.c ameth_lib.c f_int.c f_string.c
x_pkey.c bio_asn1.c bio_ndef.c asn_mime.c
asn1_gen.c asn1_parse.c asn1_lib.c asn1_err.c a_strnid.c
evp_asn1.c asn_pack.c p5_pbe.c p5_pbev2.c p5_scrypt.c p8_pkey.c
asn_moid.c asn_mstbl.c asn1_item_list.c d2i_param.c
n_pkey.c (rsa+rc4 enabled)
x_long.c (deprecated-3.0)
```

---

### 11. PEM (`crypto/pem/`)

**Sources:**
```
pem_sign.c pem_info.c pem_lib.c pem_all.c pem_err.c
pem_x509.c pem_xaux.c pem_oth.c pem_pk8.c pem_pkey.c pvkfmt.c
```

---

### 12. X509 (`crypto/x509/`)

**Sources:**
```
x509_def.c x509_d2.c x509_r2x.c x509_cmp.c x509_obj.c x509_req.c 
x509spki.c x509_vfy.c x509_set.c x509cset.c x509rset.c x509_err.c
x509name.c x509_v3.c x509_ext.c x509_att.c x509_meth.c x509_lu.c 
x_all.c x509_txt.c x509_trust.c by_file.c by_dir.c by_store.c x509_vpm.c
x_crl.c t_crl.c x_req.c t_req.c x_x509.c t_x509.c
x_pubkey.c x_x509a.c x_attrib.c x_exten.c x_name.c
v3_bcons.c v3_bitst.c v3_conf.c v3_extku.c v3_ia5.c v3_utf8.c v3_lib.c
v3_prn.c v3_utl.c v3err.c v3_genn.c v3_san.c v3_skid.c v3_akid.c
v3_pku.c v3_int.c v3_enum.c v3_sxnet.c v3_cpols.c v3_crld.c v3_purp.c
v3_info.c v3_akeya.c v3_pmaps.c v3_pcons.c v3_ncons.c
v3_pcia.c v3_pci.c v3_ist.c
pcy_cache.c pcy_node.c pcy_data.c pcy_map.c pcy_tree.c pcy_lib.c
v3_asid.c v3_addr.c v3_tlsf.c v3_admis.c v3_no_rev_avail.c
v3_soa_id.c v3_no_ass.c v3_group_ac.c v3_single_use.c v3_ind_iss.c
x509_acert.c x509aset.c t_acert.c x_ietfatt.c v3_ac_tgt.c v3_sda.c
v3_usernotice.c v3_battcons.c v3_audit_id.c v3_iobo.c v3_authattid.c
v3_rolespec.c v3_attrdesc.c v3_timespec.c v3_attrmap.c v3_aaa.c
x509type.c (deprecated-3.0)
```

---

### 13. Conf (`crypto/conf/`)

**Sources:**
```
conf_err.c conf_lib.c conf_api.c conf_def.c conf_mod.c
conf_mall.c conf_sap.c conf_ssl.c
```

---

### 14. TXT_DB (`crypto/txt_db/`)

**Sources:**
```
txt_db.c
```

---

### 15. PKCS7 (`crypto/pkcs7/`)

**Sources:**
```
pk7_asn1.c pk7_lib.c pkcs7err.c pk7_doit.c pk7_smime.c pk7_attr.c
pk7_mime.c bio_pk7.c
```

---

### 16. PKCS12 (`crypto/pkcs12/`)

**Sources:**
```
p12_add.c p12_asn.c p12_attr.c p12_crpt.c p12_crt.c p12_decr.c
p12_init.c p12_key.c p12_kiss.c p12_mutl.c p12_sbag.c
p12_utl.c p12_npas.c pk12err.c p12_p8d.c p12_p8e.c
```

---

### 17. UI (`crypto/ui/`)

**Sources:**
```
ui_err.c ui_lib.c ui_openssl.c ui_null.c ui_util.c
```

---

### 18. KDF (`crypto/kdf/`)

**Sources:**
```
kdf_err.c
```

---

### 19. Store (`crypto/store/`)

**Sources:**
```
store_err.c store_lib.c store_result.c store_strings.c store_meth.c
store_init.c store_register.c (deprecated-3.0)
```

---

### 20. Property (`crypto/property/`)

**Sources:**
```
property_string.c property_parse.c property_query.c property.c 
defn_cache.c property_err.c
```

---

### 21. ERR (`crypto/err/`)

**Sources:**
```
err_blocks.c err_mark.c err.c err_all.c err_all_legacy.c err_prn.c err_save.c
```

---

### 22. BN (`crypto/bn/`)

**Sources (no-asm):**
```
bn_asm.c (portable fallback)
bn_add.c bn_div.c bn_exp.c bn_lib.c bn_ctx.c bn_mul.c
bn_mod.c bn_conv.c bn_rand.c bn_shift.c bn_word.c bn_blind.c
bn_kron.c bn_sqrt.c bn_gcd.c bn_prime.c bn_sqr.c
bn_recp.c bn_mont.c bn_mpi.c bn_exp2.c bn_gf2m.c bn_nist.c
bn_intern.c bn_dh.c bn_rsa_fips186_4.c bn_const.c
bn_print.c bn_err.c bn_srp.c
bn_depr.c (deprecated-0.9.8)
bn_x931p.c (deprecated-3.0)
```

---

### 23. RSA (`crypto/rsa/`)

**Sources:**
```
rsa_ossl.c rsa_gen.c rsa_lib.c rsa_sign.c rsa_pk1.c
rsa_none.c rsa_oaep.c rsa_chk.c rsa_pss.c rsa_x931.c rsa_crpt.c
rsa_sp800_56b_gen.c rsa_sp800_56b_check.c rsa_backend.c
rsa_mp_names.c rsa_schemes.c
rsa_saos.c rsa_err.c rsa_asn1.c rsa_ameth.c rsa_prn.c
rsa_pmeth.c rsa_meth.c rsa_mp.c
rsa_depr.c (deprecated-0.9.8)
rsa_x931g.c (deprecated-3.0)
```

---

### 24. DSA (`crypto/dsa/`)

**Sources:**
```
dsa_sign.c dsa_vrf.c dsa_lib.c dsa_ossl.c dsa_check.c
dsa_key.c dsa_backend.c dsa_gen.c
dsa_asn1.c dsa_err.c dsa_ameth.c dsa_pmeth.c dsa_prn.c dsa_meth.c
dsa_depr.c (deprecated-0.9.8)
```

---

### 25. DH (`crypto/dh/`)

**Sources:**
```
dh_lib.c dh_key.c dh_group_params.c dh_check.c dh_backend.c dh_gen.c dh_kdf.c
dh_asn1.c dh_err.c dh_ameth.c dh_pmeth.c dh_prn.c dh_rfc5114.c dh_meth.c
dh_depr.c (deprecated-0.9.8)
```

---

### 26. EC (`crypto/ec/`)

**Sources (no-asm):**
```
ec_lib.c ecp_smpl.c ecp_mont.c ecp_nist.c ec_cvt.c ec_mult.c
ec_curve.c ec_check.c ec_key.c ec_kmeth.c ec_asn1.c
ec2_smpl.c ecp_oct.c ec2_oct.c ec_oct.c ecdh_ossl.c
ecdsa_ossl.c ecdsa_sign.c ecdsa_vrf.c ec_backend.c ecdh_kdf.c

# ECX (curve25519/448) - enabled by default
curve25519.c curve448/f_generic.c curve448/scalar.c
curve448/arch_64/f_impl64.c ecx_backend.c curve448/arch_32/f_impl32.c
curve448/curve448_tables.c curve448/eddsa.c curve448/curve448.c ecx_key.c

ec_ameth.c ec_pmeth.c ec_err.c eck_prn.c ec_deprecated.c ec_print.c
ecx_meth.c (ecx enabled)
```

**Exclusions:**
- `ecp_nistz256*.c/S` (asm-specific)
- `x25519-*.s` (asm-specific)
- `ecp_s390x*.c` (platform-specific)
- `ecx_s390x.c` (platform-specific)
- `ecp_sm2p256*.c/S` (sm2 asm)

---

### 27. SM2 (`crypto/sm2/`)

**Sources:**
```
sm2_sign.c sm2_crypt.c sm2_key.c sm2_err.c
```

**Note:** SM2 may be disabled. Check if needed.

---

### 28. DSO (`crypto/dso/`)

**Sources:**
```
dso_dl.c dso_dlfcn.c dso_err.c dso_lib.c dso_openssl.c dso_win32.c dso_vms.c
```

---

### 29. Engine (`crypto/engine/`)

**Sources:**
```
eng_err.c eng_lib.c eng_list.c eng_init.c eng_ctrl.c
eng_table.c eng_pkey.c eng_fat.c eng_all.c
tb_rsa.c tb_dsa.c tb_dh.c tb_rand.c
tb_cipher.c tb_digest.c tb_pkmeth.c tb_asnmth.c tb_eckey.c
eng_openssl.c eng_cnf.c eng_dyn.c eng_rdrand.c
```

---

### 30. AES (`crypto/aes/`)

**Sources (no-asm):**
```
aes_core.c aes_cbc.c (portable implementations)
aes_misc.c aes_ecb.c aes_cfb.c aes_ofb.c aes_wrap.c
aes_ige.c (deprecated-3.0)
```

**Exclusions:**
- All `*.S` and `*.s` assembly files
- `aes_x86core.c` (duplicate of aes_core.c)

---

### 31. DES (`crypto/des/`)

**Sources (no-asm):**
```
des_enc.c fcrypt_b.c (portable)
set_key.c ecb3_enc.c ecb_enc.c cbc_enc.c
cfb64enc.c cfb64ede.c cfb_enc.c
ofb64ede.c ofb64enc.c ofb_enc.c
str2key.c pcbc_enc.c qud_cksm.c rand_key.c
fcrypt.c xcbc_enc.c cbc_cksm.c
```

---

### 32. ChaCha (`crypto/chacha/`)

**Sources (no-asm):**
```
chacha_enc.c
```

---

### 33. Poly1305 (`crypto/poly1305/`)

**Sources (no-asm):**
```
poly1305.c
```

---

### 34. Modes (`crypto/modes/`)

**Sources (no-asm):**
```
cbc128.c ctr128.c cfb128.c ofb128.c gcm128.c ccm128.c xts128.c
wrap128.c xts128gb.c cts128.c ocb128.c siv128.c
```

---

### 35. SHA (`crypto/sha/`)

**Sources (no-asm):**
```
sha1dgst.c sha256.c sha512.c sha3.c keccak1600.c sha1_one.c
```

---

### 36. MD5 (`crypto/md5/`)

**Sources (no-asm):**
```
md5_dgst.c md5_one.c md5_sha1.c
```

---

### 37. RIPEMD (`crypto/ripemd/`)

**Sources (no-asm):**
```
rmd_dgst.c rmd_one.c
```

---

### 38. HMAC (`crypto/hmac/`)

**Sources:**
```
hmac.c
```

---

### 39. CMAC (`crypto/cmac/`)

**Sources:**
```
cmac.c
```

---

### 40. SipHash (`crypto/siphash/`)

**Sources:**
```
siphash.c
```

---

### 41. OCSP (`crypto/ocsp/`)

**Sources:**
```
ocsp_asn.c ocsp_ext.c ocsp_http.c ocsp_lib.c ocsp_cl.c
ocsp_srv.c ocsp_prn.c ocsp_vfy.c ocsp_err.c v3_ocsp.c
```

---

### 42. CMS (`crypto/cms/`)

**Sources:**
```
cms_lib.c cms_asn1.c cms_att.c cms_io.c cms_smime.c cms_err.c
cms_sd.c cms_dd.c cms_cd.c cms_env.c cms_enc.c cms_ess.c
cms_pwri.c cms_kari.c cms_rsa.c cms_dh.c cms_ec.c cms_kem.c cms_kemri.c
```

---

### 43. TS (`crypto/ts/`)

**Sources:**
```
ts_err.c ts_req_utils.c ts_req_print.c ts_rsp_utils.c ts_rsp_print.c
ts_rsp_sign.c ts_rsp_verify.c ts_verify_ctx.c ts_lib.c ts_conf.c ts_asn1.c
```

---

### 44. CT (`crypto/ct/`)

**Sources:**
```
ct_b64.c ct_err.c ct_log.c ct_oct.c ct_policy.c
ct_prn.c ct_sct.c ct_sct_ctx.c ct_vfy.c ct_x509v3.c
```

---

### 45. Comp (`crypto/comp/`)

**Sources:**
```
comp_lib.c comp_err.c c_brotli.c c_zstd.c c_zlib.c
```

---

### 46. HTTP (`crypto/http/`)

**Sources:**
```
http_lib.c http_client.c http_err.c
```

---

### 47. SRP (`crypto/srp/`)

**Sources:**
```
srp_lib.c srp_vfy.c
```

---

### 48. CMP (`crypto/cmp/`)

**Sources:**
```
cmp_asn.c cmp_ctx.c cmp_err.c cmp_util.c
cmp_status.c cmp_hdr.c cmp_protect.c cmp_msg.c cmp_vfy.c
cmp_server.c cmp_client.c cmp_genm.c cmp_http.c
```

---

### 49. CRMF (`crypto/crmf/`)

**Sources:**
```
crmf_asn.c crmf_err.c crmf_lib.c crmf_pbm.c
```

---

### 50. ESS (`crypto/ess/`)

**Sources:**
```
ess_asn1.c ess_err.c ess_lib.c
```

---

### 51. Async (`crypto/async/`)

**Sources:**
```
async.c async_wait.c async_err.c 
arch/async_posix.c arch/async_win.c arch/async_null.c
```

---

### 52. Thread (`crypto/thread/`)

**Sources:**
```
api.c arch/thread_win.c arch/thread_posix.c arch/thread_none.c
internal.c arch.c (if thread-pool enabled)
```

---

### 53. FFC (`crypto/ffc/`)

**Sources:**
```
ffc_params.c ffc_params_generate.c ffc_key_generate.c
ffc_params_validate.c ffc_key_validate.c ffc_backend.c ffc_dh.c
```

---

### 54. HPKE (`crypto/hpke/`)

**Sources:**
```
hpke_util.c hpke.c
```

---

### 55. Encode/Decode (`crypto/encode_decode/`)

**Sources:**
```
encoder_meth.c encoder_lib.c encoder_pkey.c
decoder_meth.c decoder_lib.c decoder_pkey.c
encoder_err.c decoder_err.c
```

---

### 56. ML-KEM (`crypto/ml_kem/`)

**Sources:** (Post-quantum - check build.info)

---

### 57. ML-DSA (`crypto/ml_dsa/`)

**Sources:** (Post-quantum - check build.info)

---

### 58. SLH-DSA (`crypto/slh_dsa/`)

**Sources:** (Post-quantum - check build.info)

---

### 59. LMS (`crypto/lms/`)

**Sources:** (Post-quantum - check build.info)

---

## Global Exclusions for subtree.yaml

```yaml
exclude:
  # Assembly (no-asm build)
  - '**/*.S'
  - '**/*.s'
  - '**/asm/**'
  
  # Platform-specific
  - '**/*_win32*'
  - '**/*_win.*'
  - '**/*_vms*'
  - '**/*_wince*'
  - '**/LPdir_win*'
  - '**/LPdir_vms*'
  - '**/LPdir_wince*'
  - '**/LPdir_nyi*'
  - '**/dllmain.c'
  - '**/winstore*'
  
  # Tests
  - '**/*_test*'
  - '**/test_*'
  - '**/bench*'
  - '**/*acvp*'
  
  # Duplicates
  - '**/aes_x86core.c'  # Duplicate of aes_core.c
  
  # Platform entropy
  - '**/rand_vxworks*'
  - '**/rand_egd*'
```

---

## Recommended subtree.yaml Structure

```yaml
libcrypto:
  # Public headers
  - from: ['include/openssl/**/*.h']
    to: Sources/libcrypto/include/
    exclude: ['**/*LOGUE.H']
  
  # Internal headers  
  - from: ['include/internal/**/*.h', 'include/crypto/**/*.{h,def}']
    to: Sources/libcrypto/internal_include/
  
  # All crypto sources
  - from: ['crypto/**/*.c']
    to: Sources/libcrypto/src/
    exclude:
      - '**/*.S'
      - '**/*.s'
      - '**/asm/**'
      - '**/*_test*'
      - '**/test_*'
      - '**/aes_x86core.c'
      - '**/LPdir_win*'
      - '**/LPdir_vms*'
      - '**/LPdir_wince*'
      - '**/LPdir_nyi*'
      - '**/*_win32*'
      - '**/*_vms*'
      - '**/dllmain.c'
      - '**/uplink*.c'
```

---

## Final Exclusions Summary (Verified Build)

Based on successful build with `./Configure darwin64-arm64-cc no-asm no-shared no-apps no-docs no-tests`:

### Assembly (`no-asm` build)
Per various `build.info` files, when `$disabled{asm}` is true:
- `**/*.S`, `**/*.s` - Assembly source files
- `**/asm/**` - Assembly subdirectories (e.g., `bn/asm/x86_64-gcc.c`)
- `**/perlasm/**` - Perl assembly generators

### Architecture-Specific (per `crypto/build.info:27-64`)
- `**/armcap.c`, `**/ppccap.c`, `**/sparcv9cap.c`, `**/s390xcap.c`
- `**/riscvcap.c`, `**/loongarchcap.c`
- `**/poly1305_ieee754.c`, `**/poly1305_base2_44.c`, `**/poly1305_ppc.c`
- `**/sha_ppc.c`, `**/sha_riscv.c`, `**/sm3_riscv.c`
- `**/chacha_ppc.c`, `**/chacha_riscv.c`, `**/ecp_ppc.c`, `**/md5_riscv.c`

### EC Optimizations (per `crypto/ec/build.info:84-86`)
When `$disabled{'ec_nistp_64_gcc_128'}`:
- `**/ecp_nistp224.c`, `**/ecp_nistp256.c`, `**/ecp_nistp384.c`
- `**/ecp_nistp521.c`, `**/ecp_nistputil.c`

### Assembly Duplicates (per various `build.info` files)
- `**/aes_x86core.c`, `**/rsaz_exp*.c`
- `**/ecp_nistz*.c`, `**/ecp_s390x*.c`, `**/ecx_s390x.c`
- `**/ecp_sm2p256*.c`, `**/bn_s390x.c`, `**/hmac_s390x.c`

### Legacy Algorithms (per `crypto/evp/build.info:36-63`)
When `$disabled{xxx}`:
| Algorithm | Directory | EVP Wrapper |
|-----------|-----------|-------------|
| `md2` | `**/md2/**` | `**/evp/legacy_md2.c` |
| `md4` | `**/md4/**` | `**/evp/legacy_md4.c` |
| `mdc2` | `**/mdc2/**` | `**/evp/legacy_mdc2.c` |
| `whirlpool` | `**/whrlpool/**` | `**/evp/legacy_wp.c` |
| `bf` | `**/bf/**` | `**/evp/e_bf.c` |
| `cast` | `**/cast/**` | `**/evp/e_cast.c` |
| `idea` | `**/idea/**` | `**/evp/e_idea.c` |
| `rc2` | `**/rc2/**` | `**/evp/e_rc2.c` |
| `rc5` | `**/rc5/**` | `**/evp/e_rc5.c` |
| `seed` | `**/seed/**` | `**/evp/e_seed.c` |
| `camellia` | `**/camellia/**` | `**/evp/e_camellia.c` |

### Post-Quantum Algorithms (per individual `build.info` files)
When `$disabled{xxx}`:
- `**/lms/**` - Leighton-Micali Signatures (`crypto/lms/build.info:6`)
- `**/ml_dsa/**` - ML-DSA (`crypto/ml_dsa/build.info:7`)
- `**/ml_kem/**` - ML-KEM (`crypto/ml_kem/build.info`)
- `**/slh_dsa/**` - SLH-DSA (`crypto/slh_dsa/build.info`)

### Platform-Specific (per `crypto/o_dir.c:26-37`)
- `**/LPdir_win*.c`, `**/LPdir_vms.c`, `**/LPdir_wince.c`, `**/LPdir_nyi.c`
- `**/dllmain.c`, `**/uplink*.c`
- `**/rand_vxworks*`, `**/rand_egd*`

### Files Excluded from Compilation (Package.swift)
These files are `#include`d by other source files, not compiled separately:
- `src/crypto/LPdir_unix.c` - `#include`d by `o_dir.c` (line 28)
- `src/crypto/des/ncbc_enc.c` - `#include`d by `cbc_enc.c`

### Required OPENSSL_NO_* Defines (Package.swift cSettings)
```swift
// Build configuration
.define("OPENSSL_NO_ASM"),
.define("OPENSSL_PIC"),
.define("OPENSSLDIR", to: "\"/usr/local/ssl\""),
.define("ENGINESDIR", to: "\"/usr/local/lib/engines\""),
.define("MODULESDIR", to: "\"/usr/local/lib/ossl-modules\""),

// Legacy algorithms
.define("OPENSSL_NO_RC5"),
.define("OPENSSL_NO_RC2"),
.define("OPENSSL_NO_IDEA"),
.define("OPENSSL_NO_BF"),
.define("OPENSSL_NO_CAST"),
.define("OPENSSL_NO_SEED"),
.define("OPENSSL_NO_CAMELLIA"),
.define("OPENSSL_NO_MDC2"),
.define("OPENSSL_NO_WHIRLPOOL"),
.define("OPENSSL_NO_MD2"),
.define("OPENSSL_NO_MD4"),

// Post-quantum algorithms
.define("OPENSSL_NO_LMS"),
.define("OPENSSL_NO_ML_DSA"),
.define("OPENSSL_NO_ML_KEM"),
.define("OPENSSL_NO_SLH_DSA"),

// EC optimizations
.define("OPENSSL_NO_EC_NISTP_64_GCC_128"),
```
