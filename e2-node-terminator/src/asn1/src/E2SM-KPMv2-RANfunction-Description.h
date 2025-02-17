/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "E2SM-KPM-IEs"
 * 	found in "asn1/e2sm_kpm_v2.0.3-changed.asn"
 * 	`asn1c -gen-APER -gen-UPER -no-gen-JER -no-gen-BER -no-gen-OER -fcompound-names -no-gen-example -findirect-choice -fno-include-deps -fincludes-quoted -D src`
 */

#ifndef	_E2SM_KPMv2_RANfunction_Description_H_
#define	_E2SM_KPMv2_RANfunction_Description_H_


#include "asn_application.h"

/* Including external dependencies */
#include "RANfunction-Name-KPMv2.h"
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RIC_KPMNode_Item_KPMv2;
struct RIC_EventTriggerStyle_Item_KPMv2;
struct RIC_ReportStyle_Item_KPMv2;

/* E2SM-KPMv2-RANfunction-Description */
typedef struct E2SM_KPMv2_RANfunction_Description {
	RANfunction_Name_KPMv2_t	 ranFunction_Name;
	struct E2SM_KPMv2_RANfunction_Description__ric_KPM_Node_List {
		A_SEQUENCE_OF(struct RIC_KPMNode_Item_KPMv2) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *ric_KPM_Node_List;
	struct E2SM_KPMv2_RANfunction_Description__ric_EventTriggerStyle_List {
		A_SEQUENCE_OF(struct RIC_EventTriggerStyle_Item_KPMv2) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *ric_EventTriggerStyle_List;
	struct E2SM_KPMv2_RANfunction_Description__ric_ReportStyle_List {
		A_SEQUENCE_OF(struct RIC_ReportStyle_Item_KPMv2) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *ric_ReportStyle_List;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} E2SM_KPMv2_RANfunction_Description_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_E2SM_KPMv2_RANfunction_Description;

#ifdef __cplusplus
}
#endif

#endif	/* _E2SM_KPMv2_RANfunction_Description_H_ */
#include "asn_internal.h"
