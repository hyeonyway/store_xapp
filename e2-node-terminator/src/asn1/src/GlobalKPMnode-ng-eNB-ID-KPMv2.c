/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "E2SM-KPM-IEs"
 * 	found in "asn1/e2sm_kpm_v2.0.3-changed.asn"
 * 	`asn1c -gen-APER -gen-UPER -no-gen-JER -no-gen-BER -no-gen-OER -fcompound-names -no-gen-example -findirect-choice -fno-include-deps -fincludes-quoted -D src`
 */

#include "GlobalKPMnode-ng-eNB-ID-KPMv2.h"

asn_TYPE_member_t asn_MBR_GlobalKPMnode_ng_eNB_ID_KPMv2_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct GlobalKPMnode_ng_eNB_ID_KPMv2, global_ng_eNB_ID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GlobalngeNB_ID_KPMv2,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"global-ng-eNB-ID"
		},
	{ ATF_POINTER, 1, offsetof(struct GlobalKPMnode_ng_eNB_ID_KPMv2, gNB_DU_ID),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GNB_DU_ID_KPMv2,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"gNB-DU-ID"
		},
};
static const int asn_MAP_GlobalKPMnode_ng_eNB_ID_KPMv2_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_GlobalKPMnode_ng_eNB_ID_KPMv2_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_GlobalKPMnode_ng_eNB_ID_KPMv2_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* global-ng-eNB-ID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* gNB-DU-ID */
};
asn_SEQUENCE_specifics_t asn_SPC_GlobalKPMnode_ng_eNB_ID_KPMv2_specs_1 = {
	sizeof(struct GlobalKPMnode_ng_eNB_ID_KPMv2),
	offsetof(struct GlobalKPMnode_ng_eNB_ID_KPMv2, _asn_ctx),
	asn_MAP_GlobalKPMnode_ng_eNB_ID_KPMv2_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_GlobalKPMnode_ng_eNB_ID_KPMv2_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	2,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_GlobalKPMnode_ng_eNB_ID_KPMv2 = {
	"GlobalKPMnode-ng-eNB-ID-KPMv2",
	"GlobalKPMnode-ng-eNB-ID-KPMv2",
	&asn_OP_SEQUENCE,
	asn_DEF_GlobalKPMnode_ng_eNB_ID_KPMv2_tags_1,
	sizeof(asn_DEF_GlobalKPMnode_ng_eNB_ID_KPMv2_tags_1)
		/sizeof(asn_DEF_GlobalKPMnode_ng_eNB_ID_KPMv2_tags_1[0]), /* 1 */
	asn_DEF_GlobalKPMnode_ng_eNB_ID_KPMv2_tags_1,	/* Same as above */
	sizeof(asn_DEF_GlobalKPMnode_ng_eNB_ID_KPMv2_tags_1)
		/sizeof(asn_DEF_GlobalKPMnode_ng_eNB_ID_KPMv2_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_GlobalKPMnode_ng_eNB_ID_KPMv2_1,
	2,	/* Elements count */
	&asn_SPC_GlobalKPMnode_ng_eNB_ID_KPMv2_specs_1	/* Additional specs */
};

