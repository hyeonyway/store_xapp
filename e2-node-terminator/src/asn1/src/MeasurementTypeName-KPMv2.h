/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "E2SM-KPM-IEs"
 * 	found in "asn1/e2sm_kpm_v2.0.3-changed.asn"
 * 	`asn1c -gen-APER -gen-UPER -no-gen-JER -no-gen-BER -no-gen-OER -fcompound-names -no-gen-example -findirect-choice -fno-include-deps -fincludes-quoted -D src`
 */

#ifndef	_MeasurementTypeName_KPMv2_H_
#define	_MeasurementTypeName_KPMv2_H_


#include "asn_application.h"

/* Including external dependencies */
#include "PrintableString.h"

#ifdef __cplusplus
extern "C" {
#endif

/* MeasurementTypeName-KPMv2 */
typedef PrintableString_t	 MeasurementTypeName_KPMv2_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_MeasurementTypeName_KPMv2_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_MeasurementTypeName_KPMv2;
asn_struct_free_f MeasurementTypeName_KPMv2_free;
asn_struct_print_f MeasurementTypeName_KPMv2_print;
asn_constr_check_f MeasurementTypeName_KPMv2_constraint;
xer_type_decoder_f MeasurementTypeName_KPMv2_decode_xer;
xer_type_encoder_f MeasurementTypeName_KPMv2_encode_xer;
per_type_decoder_f MeasurementTypeName_KPMv2_decode_uper;
per_type_encoder_f MeasurementTypeName_KPMv2_encode_uper;
per_type_decoder_f MeasurementTypeName_KPMv2_decode_aper;
per_type_encoder_f MeasurementTypeName_KPMv2_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _MeasurementTypeName_KPMv2_H_ */
#include "asn_internal.h"
