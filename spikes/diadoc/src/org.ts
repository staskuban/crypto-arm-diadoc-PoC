// Mapping from Diadoc Organization / Message structures to what the spike needs.
import type { Party } from './utd.ts';

// НаимРегион is mandatory in АдрРФ, Diadoc returns only the code. A few common regions are named,
// anything else gets a generic name (valid for the XSD; whether Diadoc cross-checks it is unverified).
const REGION_NAMES: Record<string, string> = {
  '50': 'Московская область',
  '66': 'Свердловская область',
  '72': 'Тюменская область',
  '77': 'г. Москва',
  '78': 'г. Санкт-Петербург',
};

export type Organization = {
  FullName?: string;
  ShortName?: string;
  Inn?: string;
  Kpp?: string;
  FnsParticipantId?: string;
  Address?: { RussianAddress?: { Region?: string; [k: string]: unknown } };
  [k: string]: unknown;
};

export function toBoxGuid(boxId: string): string {
  const hex = /^([0-9a-f]{32})@/i.exec(boxId)?.[1];
  if (hex) return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(boxId)) return boxId;
  throw new Error(`Unrecognised box id "${boxId}": expected a GUID or <32 hex>@diadoc.ru`);
}

export function partyFromOrganization(org: Organization): Party {
  if (!org.FnsParticipantId) throw new Error(`Organization ${org.Inn ?? '?'} has no FnsParticipantId (needed for the УПД file name)`);
  if (!org.Inn || org.Inn.length !== 10 || !org.Kpp) {
    throw new Error(`Organization ${org.Inn ?? '?'} is not a legal entity with INN(10)+KPP; the spike УПД only supports СвЮЛУч`);
  }
  const regionCode = org.Address?.RussianAddress?.Region || '77';
  return {
    name: org.FullName || org.ShortName || org.Inn,
    inn: org.Inn,
    kpp: org.Kpp,
    fnsParticipantId: org.FnsParticipantId,
    regionCode,
    regionName: REGION_NAMES[regionCode] ?? `Субъект РФ ${regionCode}`,
  };
}

type Entity = { EntityType?: string; EntityId?: string; ParentEntityId?: string };

/** The posted document is the Attachment entity without a parent (signatures hang under it). */
export function mainEntity(message: { Entities?: Entity[]; [k: string]: unknown }): Entity | undefined {
  return message.Entities?.find((e) => e.EntityType === 'Attachment' && !e.ParentEntityId);
}
