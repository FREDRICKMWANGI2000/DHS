import { inArray } from "drizzle-orm";
import { NodePgDatabase } from "drizzle-orm/node-postgres";
import * as schema from "./schema";
import {
  wifiPackages,
  serviceCatalog,
  NewWifiPackage,
  NewServiceCatalogItem,
  WifiPackage,
  ServiceCatalogItem,
} from "./schema";

export type DbOrTx = NodePgDatabase<typeof schema>;

export const DEFAULT_WIFI_PACKAGES: ReadonlyArray<
  Required<
    Pick<
      NewWifiPackage,
      | "name"
      | "slug"
      | "description"
      | "price"
      | "currency"
      | "durationMinutes"
      | "isActive"
      | "displayOrder"
    >
  >
> = [
  {
    name: "Quick Connect",
    slug: "quick-connect",
    description:
      "1-hour high-speed Wi-Fi access for quick browsing, messaging, and email.",
    price: "20.00",
    currency: "KES",
    durationMinutes: 60,
    isActive: true,
    displayOrder: 1,
  },
  {
    name: "Standard",
    slug: "standard",
    description:
      "2-hour high-speed Wi-Fi access ideal for study sessions, streaming, and remote tasks.",
    price: "30.00",
    currency: "KES",
    durationMinutes: 120,
    isActive: true,
    displayOrder: 2,
  },
  {
    name: "Extended",
    slug: "extended",
    description:
      "4-hour high-speed Wi-Fi access for extended work, classes, and large downloads.",
    price: "50.00",
    currency: "KES",
    durationMinutes: 240,
    isActive: true,
    displayOrder: 3,
  },
  {
    name: "Day Pass",
    slug: "day-pass",
    description:
      "8-hour full workday Wi-Fi access with reliable uninterrupted connectivity.",
    price: "80.00",
    currency: "KES",
    durationMinutes: 480,
    isActive: true,
    displayOrder: 4,
  },
  {
    name: "Full Day",
    slug: "full-day",
    description:
      "24-hour continuous high-speed Wi-Fi access for all-day and overnight connectivity.",
    price: "100.00",
    currency: "KES",
    durationMinutes: 1440,
    isActive: true,
    displayOrder: 5,
  },
];

export const DEFAULT_DIGITAL_SERVICES: ReadonlyArray<
  Required<
    Pick<
      NewServiceCatalogItem,
      | "name"
      | "slug"
      | "description"
      | "price"
      | "currency"
      | "pricingUnit"
      | "isActive"
      | "displayOrder"
    >
  >
> = [
  {
    name: "CV & Resume",
    slug: "cv-resume",
    description:
      "Professional CV and resume writing, ATS optimization, and modern layout design.",
    price: "1200.00",
    currency: "KES",
    pricingUnit: "FIXED",
    isActive: true,
    displayOrder: 1,
  },
  {
    name: "Job Applications",
    slug: "job-applications",
    description:
      "End-to-end online job application assistance, portal profile setup, and submission.",
    price: "800.00",
    currency: "KES",
    pricingUnit: "FIXED",
    isActive: true,
    displayOrder: 2,
  },
  {
    name: "Cover Letters",
    slug: "cover-letters",
    description:
      "Tailored, role-specific cover letters crafted to highlight your strengths and experience.",
    price: "600.00",
    currency: "KES",
    pricingUnit: "FIXED",
    isActive: true,
    displayOrder: 3,
  },
  {
    name: "Typing",
    slug: "typing",
    description:
      "Fast and accurate document typing from handwritten notes, scanned pages, or audio.",
    price: "200.00",
    currency: "KES",
    pricingUnit: "FIXED",
    isActive: true,
    displayOrder: 4,
  },
  {
    name: "Document Formatting",
    slug: "document-formatting",
    description:
      "Professional formatting, table of contents, pagination, styles, and layout cleanup.",
    price: "150.00",
    currency: "KES",
    pricingUnit: "FIXED",
    isActive: true,
    displayOrder: 5,
  },
  {
    name: "PDF Services",
    slug: "pdf-services",
    description:
      "PDF conversion, merging, splitting, compression, and fillable form preparation.",
    price: "100.00",
    currency: "KES",
    pricingUnit: "FIXED",
    isActive: true,
    displayOrder: 6,
  },
  {
    name: "Printing",
    slug: "printing",
    description: "Crisp, high-quality document printing charged per page.",
    price: "15.00",
    currency: "KES",
    pricingUnit: "PER_PAGE",
    isActive: true,
    displayOrder: 7,
  },
  {
    name: "Scanning",
    slug: "scanning",
    description:
      "High-resolution document and ID scanning to PDF or image formats per page.",
    price: "25.00",
    currency: "KES",
    pricingUnit: "PER_PAGE",
    isActive: true,
    displayOrder: 8,
  },
  {
    name: "Passport Photos",
    slug: "passport-photos",
    description:
      "Biometric and standard passport photo capture, background editing, and print set.",
    price: "250.00",
    currency: "KES",
    pricingUnit: "PER_SET",
    isActive: true,
    displayOrder: 9,
  },
  {
    name: "Cyber Café",
    slug: "cyber-cafe",
    description:
      "Workstation computer rental with office software and high-speed internet per hour.",
    price: "50.00",
    currency: "KES",
    pricingUnit: "PER_HOUR",
    isActive: true,
    displayOrder: 10,
  },
  {
    name: "Internet Access",
    slug: "internet-access",
    description:
      "Dedicated high-speed internet session for walk-in cyber café and hub users.",
    price: "100.00",
    currency: "KES",
    pricingUnit: "PER_SESSION",
    isActive: true,
    displayOrder: 11,
  },
];

export interface SeedItemReport<T> {
  slug: string;
  action: "INSERTED" | "PRESERVED";
  customizations: string[];
  record: T;
}

export interface CatalogSeedSummary {
  wifiPackages: {
    insertedCount: number;
    preservedCount: number;
    items: SeedItemReport<WifiPackage>[];
  };
  digitalServices: {
    insertedCount: number;
    preservedCount: number;
    items: SeedItemReport<ServiceCatalogItem>[];
  };
}

function diffWifiPackage(
  def: (typeof DEFAULT_WIFI_PACKAGES)[number],
  actual: WifiPackage
): string[] {
  const diffs: string[] = [];
  if (actual.name !== def.name) {
    diffs.push(`name: "${actual.name}" (default: "${def.name}")`);
  }
  if (actual.price !== def.price) {
    diffs.push(`price: ${actual.price} (default: ${def.price})`);
  }
  if (actual.currency !== def.currency) {
    diffs.push(`currency: ${actual.currency} (default: ${def.currency})`);
  }
  if (actual.durationMinutes !== def.durationMinutes) {
    diffs.push(
      `durationMinutes: ${actual.durationMinutes} (default: ${def.durationMinutes})`
    );
  }
  if (actual.isActive !== def.isActive) {
    diffs.push(`isActive: ${actual.isActive} (default: ${def.isActive})`);
  }
  if (actual.displayOrder !== def.displayOrder) {
    diffs.push(
      `displayOrder: ${actual.displayOrder} (default: ${def.displayOrder})`
    );
  }
  if ((actual.description ?? "") !== def.description) {
    diffs.push("description: customized");
  }
  return diffs;
}

function diffServiceCatalogItem(
  def: (typeof DEFAULT_DIGITAL_SERVICES)[number],
  actual: ServiceCatalogItem
): string[] {
  const diffs: string[] = [];
  if (actual.name !== def.name) {
    diffs.push(`name: "${actual.name}" (default: "${def.name}")`);
  }
  if (actual.price !== def.price) {
    diffs.push(`price: ${actual.price} (default: ${def.price})`);
  }
  if (actual.currency !== def.currency) {
    diffs.push(`currency: ${actual.currency} (default: ${def.currency})`);
  }
  if (actual.pricingUnit !== def.pricingUnit) {
    diffs.push(
      `pricingUnit: ${actual.pricingUnit} (default: ${def.pricingUnit})`
    );
  }
  if (actual.isActive !== def.isActive) {
    diffs.push(`isActive: ${actual.isActive} (default: ${def.isActive})`);
  }
  if (actual.displayOrder !== def.displayOrder) {
    diffs.push(
      `displayOrder: ${actual.displayOrder} (default: ${def.displayOrder})`
    );
  }
  if ((actual.description ?? "") !== def.description) {
    diffs.push("description: customized");
  }
  return diffs;
}

/**
 * Executes idempotent, insert-only catalog seeding inside the provided database or transaction context.
 * Uses ON CONFLICT (slug) DO NOTHING so administrator changes are never overwritten.
 */
export async function runCatalogSeed(
  executor: DbOrTx
): Promise<CatalogSeedSummary> {
  // 1. Insert missing Wi-Fi packages using ON CONFLICT (slug) DO NOTHING
  const insertedWifiRows = await executor
    .insert(wifiPackages)
    .values([...DEFAULT_WIFI_PACKAGES])
    .onConflictDoNothing({ target: wifiPackages.slug })
    .returning({ slug: wifiPackages.slug });

  const insertedWifiSlugs = new Set(insertedWifiRows.map((r) => r.slug));

  // Query all expected Wi-Fi packages after insertion attempt
  const wifiSlugs = DEFAULT_WIFI_PACKAGES.map((p) => p.slug);
  const currentWifiRows = await executor
    .select()
    .from(wifiPackages)
    .where(inArray(wifiPackages.slug, wifiSlugs));

  const wifiBySlug = new Map(currentWifiRows.map((r) => [r.slug, r]));

  const wifiReports: SeedItemReport<WifiPackage>[] = DEFAULT_WIFI_PACKAGES.map(
    (def) => {
      const actual = wifiBySlug.get(def.slug);
      if (!actual) {
        throw new Error(
          `Expected Wi-Fi package slug "${def.slug}" was not found after seed.`
        );
      }
      const wasInserted = insertedWifiSlugs.has(def.slug);
      const customizations = wasInserted ? [] : diffWifiPackage(def, actual);
      return {
        slug: def.slug,
        action: wasInserted ? "INSERTED" : "PRESERVED",
        customizations,
        record: actual,
      };
    }
  );

  // 2. Insert missing Digital Services using ON CONFLICT (slug) DO NOTHING
  const insertedServiceRows = await executor
    .insert(serviceCatalog)
    .values([...DEFAULT_DIGITAL_SERVICES])
    .onConflictDoNothing({ target: serviceCatalog.slug })
    .returning({ slug: serviceCatalog.slug });

  const insertedServiceSlugs = new Set(insertedServiceRows.map((r) => r.slug));

  // Query all expected Digital Services after insertion attempt
  const serviceSlugs = DEFAULT_DIGITAL_SERVICES.map((s) => s.slug);
  const currentServiceRows = await executor
    .select()
    .from(serviceCatalog)
    .where(inArray(serviceCatalog.slug, serviceSlugs));

  const serviceBySlug = new Map(currentServiceRows.map((r) => [r.slug, r]));

  const serviceReports: SeedItemReport<ServiceCatalogItem>[] =
    DEFAULT_DIGITAL_SERVICES.map((def) => {
      const actual = serviceBySlug.get(def.slug);
      if (!actual) {
        throw new Error(
          `Expected service slug "${def.slug}" was not found after seed.`
        );
      }
      const wasInserted = insertedServiceSlugs.has(def.slug);
      const customizations = wasInserted
        ? []
        : diffServiceCatalogItem(def, actual);
      return {
        slug: def.slug,
        action: wasInserted ? "INSERTED" : "PRESERVED",
        customizations,
        record: actual,
      };
    });

  return {
    wifiPackages: {
      insertedCount: insertedWifiSlugs.size,
      preservedCount: DEFAULT_WIFI_PACKAGES.length - insertedWifiSlugs.size,
      items: wifiReports,
    },
    digitalServices: {
      insertedCount: insertedServiceSlugs.size,
      preservedCount:
        DEFAULT_DIGITAL_SERVICES.length - insertedServiceSlugs.size,
      items: serviceReports,
    },
  };
}
