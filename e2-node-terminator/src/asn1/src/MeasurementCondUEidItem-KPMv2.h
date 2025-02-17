/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "E2SM-KPM-IEs"
 * 	found in "asn1/e2sm_kpm_v2.0.3-changed.asn"
 * 	`asn1c -gen-APER -gen-UPER -no-gen-JER -no-gen-BER -no-gen-OER -fcompound-names -no-gen-example -findirect-choice -fno-include-deps -fincludes-quoted -D src`
 */

#ifndef	_MeasurementCondUEidItem_KPMv2_H_
#define	_MeasurementCondUEidItem_KPMv2_H_


#include "asn_application.h"

/* Including external dependencies */
#include "MeasurementType-KPMv2.h"
#include "MatchingCondList-KPMv2.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MatchingUEidList_KPMv2;

/* MeasurementCondUEidItem-KPMv2 */
typedef struct MeasurementCondUEidItem_KPMv2 {
	MeasurementType_KPMv2_t	 measType;
	MatchingCondList_KPMv2_t	 matchingCond;
	struct MatchingUEidList_KPMv2	*matchingUEidList;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MeasurementCondUEidItem_KPMv2_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MeasurementCondUEidItem_KPMv2;
extern asn_SEQUENCE_specifics_t asn_SPC_MeasurementCondUEidItem_KPMv2_specs_1;
extern asn_TYPE_member_t asn_MBR_MeasurementCondUEidItem_KPMv2_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _MeasurementCondUEidItem_KPMv2_H_ */
#include "asn_internal.h"
