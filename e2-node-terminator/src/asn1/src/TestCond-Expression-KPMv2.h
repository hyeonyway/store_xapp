/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "E2SM-KPM-IEs"
 * 	found in "asn1/e2sm_kpm_v2.0.3-changed.asn"
 * 	`asn1c -gen-APER -gen-UPER -no-gen-JER -no-gen-BER -no-gen-OER -fcompound-names -no-gen-example -findirect-choice -fno-include-deps -fincludes-quoted -D src`
 */

#ifndef	_TestCond_Expression_KPMv2_H_
#define	_TestCond_Expression_KPMv2_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NativeEnumerated.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TestCond_Expression_KPMv2 {
	TestCond_Expression_KPMv2_equal	= 0,
	TestCond_Expression_KPMv2_greaterthan	= 1,
	TestCond_Expression_KPMv2_lessthan	= 2,
	TestCond_Expression_KPMv2_contains	= 3,
	TestCond_Expression_KPMv2_present	= 4
	/*
	 * Enumeration is extensible
	 */
} e_TestCond_Expression_KPMv2;

/* TestCond-Expression-KPMv2 */
typedef long	 TestCond_Expression_KPMv2_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_TestCond_Expression_KPMv2_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_TestCond_Expression_KPMv2;
extern const asn_INTEGER_specifics_t asn_SPC_TestCond_Expression_KPMv2_specs_1;
asn_struct_free_f TestCond_Expression_KPMv2_free;
asn_struct_print_f TestCond_Expression_KPMv2_print;
asn_constr_check_f TestCond_Expression_KPMv2_constraint;
xer_type_decoder_f TestCond_Expression_KPMv2_decode_xer;
xer_type_encoder_f TestCond_Expression_KPMv2_encode_xer;
per_type_decoder_f TestCond_Expression_KPMv2_decode_uper;
per_type_encoder_f TestCond_Expression_KPMv2_encode_uper;
per_type_decoder_f TestCond_Expression_KPMv2_decode_aper;
per_type_encoder_f TestCond_Expression_KPMv2_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _TestCond_Expression_KPMv2_H_ */
#include "asn_internal.h"
