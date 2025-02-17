/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "E2AP-IEs"
 * 	found in "asn1/e2ap_v2.asn1"
 * 	`asn1c -gen-APER -gen-UPER -no-gen-JER -no-gen-BER -no-gen-OER -fcompound-names -no-gen-example -findirect-choice -fno-include-deps -fincludes-quoted -D src`
 */

#include "GlobalE2node-en-gNB-ID.h"

asn_TYPE_member_t asn_MBR_GlobalE2node_en_gNB_ID_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct GlobalE2node_en_gNB_ID, global_en_gNB_ID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GlobalenGNB_ID,
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
		"global-en-gNB-ID"
		},
	{ ATF_POINTER, 2, offsetof(struct GlobalE2node_en_gNB_ID, en_gNB_CU_UP_ID),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GNB_CU_UP_ID,
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
		"en-gNB-CU-UP-ID"
		},
	{ ATF_POINTER, 1, offsetof(struct GlobalE2node_en_gNB_ID, en_gNB_DU_ID),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_GNB_DU_ID,
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
		"en-gNB-DU-ID"
		},
};
static const int asn_MAP_GlobalE2node_en_gNB_ID_oms_1[] = { 1, 2 };
static const ber_tlv_tag_t asn_DEF_GlobalE2node_en_gNB_ID_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_GlobalE2node_en_gNB_ID_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* global-en-gNB-ID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* en-gNB-CU-UP-ID */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* en-gNB-DU-ID */
};
asn_SEQUENCE_specifics_t asn_SPC_GlobalE2node_en_gNB_ID_specs_1 = {
	sizeof(struct GlobalE2node_en_gNB_ID),
	offsetof(struct GlobalE2node_en_gNB_ID, _asn_ctx),
	asn_MAP_GlobalE2node_en_gNB_ID_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_GlobalE2node_en_gNB_ID_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	3,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_GlobalE2node_en_gNB_ID = {
	"GlobalE2node-en-gNB-ID",
	"GlobalE2node-en-gNB-ID",
	&asn_OP_SEQUENCE,
	asn_DEF_GlobalE2node_en_gNB_ID_tags_1,
	sizeof(asn_DEF_GlobalE2node_en_gNB_ID_tags_1)
		/sizeof(asn_DEF_GlobalE2node_en_gNB_ID_tags_1[0]), /* 1 */
	asn_DEF_GlobalE2node_en_gNB_ID_tags_1,	/* Same as above */
	sizeof(asn_DEF_GlobalE2node_en_gNB_ID_tags_1)
		/sizeof(asn_DEF_GlobalE2node_en_gNB_ID_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_GlobalE2node_en_gNB_ID_1,
	3,	/* Elements count */
	&asn_SPC_GlobalE2node_en_gNB_ID_specs_1	/* Additional specs */
};

