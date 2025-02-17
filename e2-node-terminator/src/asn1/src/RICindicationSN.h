/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "E2AP-IEs"
 * 	found in "asn1/e2ap_v2.asn1"
 * 	`asn1c -gen-APER -gen-UPER -no-gen-JER -no-gen-BER -no-gen-OER -fcompound-names -no-gen-example -findirect-choice -fno-include-deps -fincludes-quoted -D src`
 */

#ifndef	_RICindicationSN_H_
#define	_RICindicationSN_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NativeInteger.h"

#ifdef __cplusplus
extern "C" {
#endif

/* RICindicationSN */
typedef long	 RICindicationSN_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_RICindicationSN_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_RICindicationSN;
asn_struct_free_f RICindicationSN_free;
asn_struct_print_f RICindicationSN_print;
asn_constr_check_f RICindicationSN_constraint;
xer_type_decoder_f RICindicationSN_decode_xer;
xer_type_encoder_f RICindicationSN_encode_xer;
per_type_decoder_f RICindicationSN_decode_uper;
per_type_encoder_f RICindicationSN_encode_uper;
per_type_decoder_f RICindicationSN_decode_aper;
per_type_encoder_f RICindicationSN_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _RICindicationSN_H_ */
#include "asn_internal.h"
