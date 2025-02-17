/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "E2SM-KPM-IEs"
 * 	found in "asn1/e2sm_kpm_v2.0.3-changed.asn"
 * 	`asn1c -gen-APER -gen-UPER -no-gen-JER -no-gen-BER -no-gen-OER -fcompound-names -no-gen-example -findirect-choice -fno-include-deps -fincludes-quoted -D src`
 */

#ifndef	_GlobalKPMnode_gNB_ID_KPMv2_H_
#define	_GlobalKPMnode_gNB_ID_KPMv2_H_


#include "asn_application.h"

/* Including external dependencies */
#include "GlobalgNB-ID-KPMv2.h"
#include "GNB-CU-UP-ID-KPMv2.h"
#include "GNB-DU-ID-KPMv2.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* GlobalKPMnode-gNB-ID-KPMv2 */
typedef struct GlobalKPMnode_gNB_ID_KPMv2 {
	GlobalgNB_ID_KPMv2_t	 global_gNB_ID;
	GNB_CU_UP_ID_KPMv2_t	*gNB_CU_UP_ID;	/* OPTIONAL */
	GNB_DU_ID_KPMv2_t	*gNB_DU_ID;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} GlobalKPMnode_gNB_ID_KPMv2_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_GlobalKPMnode_gNB_ID_KPMv2;
extern asn_SEQUENCE_specifics_t asn_SPC_GlobalKPMnode_gNB_ID_KPMv2_specs_1;
extern asn_TYPE_member_t asn_MBR_GlobalKPMnode_gNB_ID_KPMv2_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _GlobalKPMnode_gNB_ID_KPMv2_H_ */
#include "asn_internal.h"
