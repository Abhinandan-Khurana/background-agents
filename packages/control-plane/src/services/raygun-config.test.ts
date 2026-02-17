import { describe, it, expect, beforeEach, vi } from "vitest";
import { RaygunConfigService } from "./raygun-config";
import { RaygunConfigRepository } from "../db/raygun";
import type { RaygunConfig } from "@open-inspect/shared";

// Mock RaygunConfigRepository
class MockRaygunConfigRepository {
  private configs: Map<number, RaygunConfig> = new Map();
  private nextId = 1;

  async get(repoId: number): Promise<RaygunConfig | null> {
    return this.configs.get(repoId) || null;
  }

  async create(repoId: number, applicationId: string): Promise<RaygunConfig> {
    const config: RaygunConfig = {
      id: `config-${this.nextId++}`,
      repoId: String(repoId),
      applicationId,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.configs.set(repoId, config);
    return config;
  }

  async update(repoId: number, applicationId: string): Promise<RaygunConfig> {
    const existing = this.configs.get(repoId);
    if (!existing) {
      throw new Error("Raygun configuration not found");
    }
    const updated: RaygunConfig = {
      ...existing,
      applicationId,
      updatedAt: new Date(),
    };
    this.configs.set(repoId, updated);
    return updated;
  }

  async delete(repoId: number): Promise<boolean> {
    return this.configs.delete(repoId);
  }

  // Helper for testing
  clear() {
    this.configs.clear();
    this.nextId = 1;
  }
}

describe("RaygunConfigService", () => {
  let repository: MockRaygunConfigRepository;
  let service: RaygunConfigService;

  beforeEach(() => {
    repository = new MockRaygunConfigRepository();
    service = new RaygunConfigService(repository as any);
  });

  describe("validateApplicationId", () => {
    it("should accept valid UUID v4 format", () => {
      const validUUIDs = [
        "550e8400-e29b-41d4-a716-446655440000",
        "123e4567-e89b-12d3-a456-426614174000",
        "a1b2c3d4-e5f6-4890-abcd-ef1234567890",
        "00000000-0000-4000-8000-000000000000",
        "ffffffff-ffff-4fff-bfff-ffffffffffff",
      ];

      for (const uuid of validUUIDs) {
        expect(service.validateApplicationId(uuid)).toBe(true);
      }
    });

    it("should accept valid UUIDs with different casing", () => {
      const uuid = "550E8400-E29B-41D4-A716-446655440000";
      expect(service.validateApplicationId(uuid)).toBe(true);
    });

    it("should accept UUIDs with whitespace that can be trimmed", () => {
      const uuid = "  550e8400-e29b-41d4-a716-446655440000  ";
      expect(service.validateApplicationId(uuid)).toBe(true);
    });

    it("should reject invalid UUID formats", () => {
      const invalidFormats = [
        "not-a-uuid",
        "550e8400-e29b-41d4-a716",
        "550e8400-e29b-41d4-a716-446655440000-extra",
        "550e8400e29b41d4a716446655440000", // Missing hyphens
        "550e8400-e29b-51d4-a716-446655440000", // Wrong version (5 instead of 4)
        "550e8400-e29b-41d4-c716-446655440000", // Wrong variant (c instead of 8/9/a/b)
        "",
        "   ",
      ];

      for (const invalid of invalidFormats) {
        expect(service.validateApplicationId(invalid)).toBe(false);
      }
    });

    it("should reject non-string values", () => {
      expect(service.validateApplicationId(null as any)).toBe(false);
      expect(service.validateApplicationId(undefined as any)).toBe(false);
      expect(service.validateApplicationId(123 as any)).toBe(false);
      expect(service.validateApplicationId({} as any)).toBe(false);
      expect(service.validateApplicationId([] as any)).toBe(false);
    });

    it("should reject UUIDs with invalid characters", () => {
      const invalidChars = [
        "550e8400-e29b-41d4-a716-44665544000g", // 'g' is not hex
        "550e8400-e29b-41d4-a716-44665544000!", // Special character
        "550e8400-e29b-41d4-a716-44665544000 ", // Space in UUID
      ];

      for (const invalid of invalidChars) {
        expect(service.validateApplicationId(invalid)).toBe(false);
      }
    });
  });

  describe("getConfig", () => {
    it("should return null if configuration doesn't exist", async () => {
      const config = await service.getConfig(999);
      expect(config).toBeNull();
    });

    it("should retrieve an existing configuration", async () => {
      const repoId = 123;
      const applicationId = "550e8400-e29b-41d4-a716-446655440000";

      await repository.create(repoId, applicationId);
      const config = await service.getConfig(repoId);

      expect(config).toBeDefined();
      expect(config?.repoId).toBe(String(repoId));
      expect(config?.applicationId).toBe(applicationId);
    });

    it("should propagate repository errors", async () => {
      const repoId = 123;
      const errorRepo = {
        get: vi.fn().mockRejectedValue(new Error("Database error")),
      };
      const errorService = new RaygunConfigService(errorRepo as any);

      await expect(errorService.getConfig(repoId)).rejects.toThrow("Database error");
    });
  });

  describe("setConfig", () => {
    it("should create a new configuration if none exists", async () => {
      const repoId = 123;
      const applicationId = "550e8400-e29b-41d4-a716-446655440000";

      const config = await service.setConfig(repoId, applicationId);

      expect(config).toBeDefined();
      expect(config.repoId).toBe(String(repoId));
      expect(config.applicationId).toBe(applicationId);
      expect(config.id).toBeDefined();
      expect(config.createdAt).toBeInstanceOf(Date);
      expect(config.updatedAt).toBeInstanceOf(Date);
    });

    it("should update an existing configuration", async () => {
      const repoId = 123;
      const oldApplicationId = "550e8400-e29b-41d4-a716-446655440000";
      const newApplicationId = "660e8400-e29b-41d4-a716-446655440001";

      const created = await service.setConfig(repoId, oldApplicationId);
      const updated = await service.setConfig(repoId, newApplicationId);

      expect(updated.id).toBe(created.id);
      expect(updated.applicationId).toBe(newApplicationId);
      expect(updated.repoId).toBe(String(repoId));
    });

    it("should reject invalid Application ID format", async () => {
      const repoId = 123;
      const invalidId = "not-a-uuid";

      await expect(service.setConfig(repoId, invalidId)).rejects.toThrow(
        "Invalid Application ID format"
      );
    });

    it("should reject empty Application ID", async () => {
      const repoId = 123;

      await expect(service.setConfig(repoId, "")).rejects.toThrow(
        "Invalid Application ID format"
      );
    });

    it("should reject Application ID with wrong UUID version", async () => {
      const repoId = 123;
      const wrongVersion = "550e8400-e29b-51d4-a716-446655440000"; // Version 5

      await expect(service.setConfig(repoId, wrongVersion)).rejects.toThrow(
        "Invalid Application ID format"
      );
    });

    it("should accept Application ID with whitespace (trimmed)", async () => {
      const repoId = 123;
      const applicationId = "  550e8400-e29b-41d4-a716-446655440000  ";

      const config = await service.setConfig(repoId, applicationId);
      expect(config).toBeDefined();
    });

    it("should validate before attempting to save", async () => {
      const repoId = 123;
      const invalidId = "invalid";

      // Mock repository to track if create was called
      const createSpy = vi.spyOn(repository, "create");

      await expect(service.setConfig(repoId, invalidId)).rejects.toThrow();
      expect(createSpy).not.toHaveBeenCalled();
    });

    it("should propagate repository errors", async () => {
      const repoId = 123;
      const applicationId = "550e8400-e29b-41d4-a716-446655440000";

      const errorRepo = {
        get: vi.fn().mockResolvedValue(null),
        create: vi.fn().mockRejectedValue(new Error("Database error")),
      };
      const errorService = new RaygunConfigService(errorRepo as any);

      await expect(errorService.setConfig(repoId, applicationId)).rejects.toThrow(
        "Database error"
      );
    });
  });

  describe("deleteConfig", () => {
    it("should delete an existing configuration", async () => {
      const repoId = 123;
      const applicationId = "550e8400-e29b-41d4-a716-446655440000";

      await repository.create(repoId, applicationId);
      await service.deleteConfig(repoId);

      const config = await service.getConfig(repoId);
      expect(config).toBeNull();
    });

    it("should not throw error if configuration doesn't exist", async () => {
      const repoId = 999;

      await expect(service.deleteConfig(repoId)).resolves.not.toThrow();
    });

    it("should propagate repository errors", async () => {
      const repoId = 123;
      const errorRepo = {
        delete: vi.fn().mockRejectedValue(new Error("Database error")),
      };
      const errorService = new RaygunConfigService(errorRepo as any);

      await expect(errorService.deleteConfig(repoId)).rejects.toThrow("Database error");
    });
  });

  describe("integration scenarios", () => {
    it("should handle create-update-delete lifecycle", async () => {
      const repoId = 123;
      const app1 = "550e8400-e29b-41d4-a716-446655440000";
      const app2 = "660e8400-e29b-41d4-a716-446655440001";

      // Create
      const created = await service.setConfig(repoId, app1);
      expect(created.applicationId).toBe(app1);

      // Update
      const updated = await service.setConfig(repoId, app2);
      expect(updated.applicationId).toBe(app2);
      expect(updated.id).toBe(created.id);

      // Verify update
      const retrieved = await service.getConfig(repoId);
      expect(retrieved?.applicationId).toBe(app2);

      // Delete
      await service.deleteConfig(repoId);

      // Verify deletion
      const afterDelete = await service.getConfig(repoId);
      expect(afterDelete).toBeNull();
    });

    it("should handle multiple repositories independently", async () => {
      const repo1 = 123;
      const repo2 = 456;
      const app1 = "550e8400-e29b-41d4-a716-446655440000";
      const app2 = "660e8400-e29b-41d4-a716-446655440001";

      await service.setConfig(repo1, app1);
      await service.setConfig(repo2, app2);

      const config1 = await service.getConfig(repo1);
      const config2 = await service.getConfig(repo2);

      expect(config1?.applicationId).toBe(app1);
      expect(config2?.applicationId).toBe(app2);

      // Delete one shouldn't affect the other
      await service.deleteConfig(repo1);

      const afterDelete1 = await service.getConfig(repo1);
      const afterDelete2 = await service.getConfig(repo2);

      expect(afterDelete1).toBeNull();
      expect(afterDelete2?.applicationId).toBe(app2);
    });

    it("should validate on every setConfig call", async () => {
      const repoId = 123;
      const validId = "550e8400-e29b-41d4-a716-446655440000";
      const invalidId = "not-a-uuid";

      // Create with valid ID
      await service.setConfig(repoId, validId);

      // Try to update with invalid ID
      await expect(service.setConfig(repoId, invalidId)).rejects.toThrow(
        "Invalid Application ID format"
      );

      // Verify original value is preserved
      const config = await service.getConfig(repoId);
      expect(config?.applicationId).toBe(validId);
    });
  });

  describe("error handling", () => {
    it("should provide meaningful error message for invalid format", async () => {
      const repoId = 123;
      const invalidId = "12345";

      try {
        await service.setConfig(repoId, invalidId);
        expect.fail("Should have thrown an error");
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
        expect((e as Error).message).toContain("Invalid Application ID format");
        expect((e as Error).message).toContain("UUID format");
      }
    });

    it("should handle repository get errors gracefully", async () => {
      const repoId = 123;
      const errorRepo = {
        get: vi.fn().mockRejectedValue(new Error("Connection timeout")),
      };
      const errorService = new RaygunConfigService(errorRepo as any);

      await expect(errorService.getConfig(repoId)).rejects.toThrow("Connection timeout");
    });

    it("should handle repository create errors gracefully", async () => {
      const repoId = 123;
      const applicationId = "550e8400-e29b-41d4-a716-446655440000";

      const errorRepo = {
        get: vi.fn().mockResolvedValue(null),
        create: vi.fn().mockRejectedValue(new Error("Constraint violation")),
      };
      const errorService = new RaygunConfigService(errorRepo as any);

      await expect(errorService.setConfig(repoId, applicationId)).rejects.toThrow(
        "Constraint violation"
      );
    });

    it("should handle repository update errors gracefully", async () => {
      const repoId = 123;
      const applicationId = "550e8400-e29b-41d4-a716-446655440000";

      const existingConfig: RaygunConfig = {
        id: "config-1",
        repoId: String(repoId),
        applicationId: "old-id",
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const errorRepo = {
        get: vi.fn().mockResolvedValue(existingConfig),
        update: vi.fn().mockRejectedValue(new Error("Update failed")),
      };
      const errorService = new RaygunConfigService(errorRepo as any);

      await expect(errorService.setConfig(repoId, applicationId)).rejects.toThrow(
        "Update failed"
      );
    });

    it("should handle repository delete errors gracefully", async () => {
      const repoId = 123;
      const errorRepo = {
        delete: vi.fn().mockRejectedValue(new Error("Delete failed")),
      };
      const errorService = new RaygunConfigService(errorRepo as any);

      await expect(errorService.deleteConfig(repoId)).rejects.toThrow("Delete failed");
    });
  });
});
