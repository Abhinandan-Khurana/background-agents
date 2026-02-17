import { describe, it, expect, beforeEach } from "vitest";
import { RaygunConfigRepository } from "./raygun";
import { generateEncryptionKey } from "../auth/crypto";

// Mock D1 database for testing
class MockD1Database {
  private data: Map<number, any> = new Map();

  prepare(query: string) {
    return new MockD1PreparedStatement(query, this.data);
  }

  batch(statements: any[]) {
    return Promise.all(statements.map((s: any) => s.run()));
  }
}

class MockD1PreparedStatement {
  private bindings: any[] = [];

  constructor(
    private query: string,
    private data: Map<number, any>
  ) {}

  bind(...values: any[]) {
    this.bindings = values;
    return this;
  }

  async first<T>(): Promise<T | null> {
    if (this.query.includes("SELECT") && this.query.includes("WHERE repo_id = ?")) {
      const repoId = this.bindings[0];
      return (this.data.get(repoId) as T) || null;
    }
    return null;
  }

  async run() {
    if (this.query.includes("INSERT INTO raygun_configs")) {
      const [id, repoId, encrypted, createdAt, updatedAt] = this.bindings;
      this.data.set(repoId, {
        id,
        repo_id: repoId,
        application_id_encrypted: encrypted,
        created_at: createdAt,
        updated_at: updatedAt,
      });
      return { success: true, meta: { changes: 1 } };
    }

    if (this.query.includes("UPDATE raygun_configs")) {
      const [encrypted, updatedAt, repoId] = this.bindings;
      const existing = this.data.get(repoId);
      if (existing) {
        this.data.set(repoId, {
          ...existing,
          application_id_encrypted: encrypted,
          updated_at: updatedAt,
        });
        return { success: true, meta: { changes: 1 } };
      }
      return { success: false, meta: { changes: 0 } };
    }

    if (this.query.includes("DELETE FROM raygun_configs")) {
      const repoId = this.bindings[0];
      const existed = this.data.has(repoId);
      this.data.delete(repoId);
      return { success: true, meta: { changes: existed ? 1 : 0 } };
    }

    return { success: true, meta: { changes: 0 } };
  }
}

describe("RaygunConfigRepository", () => {
  let db: MockD1Database;
  let encryptionKey: string;
  let repository: RaygunConfigRepository;

  beforeEach(() => {
    db = new MockD1Database();
    encryptionKey = generateEncryptionKey();
    repository = new RaygunConfigRepository(db as any, encryptionKey);
  });

  describe("create", () => {
    it("should create a new Raygun configuration", async () => {
      const repoId = 123;
      const applicationId = "550e8400-e29b-41d4-a716-446655440000";

      const config = await repository.create(repoId, applicationId);

      expect(config).toBeDefined();
      expect(config.repoId).toBe(String(repoId));
      expect(config.applicationId).toBe(applicationId);
      expect(config.id).toBeDefined();
      expect(config.createdAt).toBeInstanceOf(Date);
      expect(config.updatedAt).toBeInstanceOf(Date);
    });

    it("should encrypt the application ID", async () => {
      const repoId = 123;
      const applicationId = "550e8400-e29b-41d4-a716-446655440000";

      await repository.create(repoId, applicationId);

      // Verify we can retrieve and decrypt it
      const retrieved = await repository.get(repoId);
      expect(retrieved?.applicationId).toBe(applicationId);
    });
  });

  describe("get", () => {
    it("should return null if configuration doesn't exist", async () => {
      const config = await repository.get(999);
      expect(config).toBeNull();
    });

    it("should retrieve and decrypt an existing configuration", async () => {
      const repoId = 123;
      const applicationId = "550e8400-e29b-41d4-a716-446655440000";

      await repository.create(repoId, applicationId);
      const retrieved = await repository.get(repoId);

      expect(retrieved).toBeDefined();
      expect(retrieved?.repoId).toBe(String(repoId));
      expect(retrieved?.applicationId).toBe(applicationId);
    });

    it("should handle decryption errors gracefully", async () => {
      const repoId = 123;
      const applicationId = "550e8400-e29b-41d4-a716-446655440000";

      await repository.create(repoId, applicationId);

      // Create a new repository with a different encryption key
      const wrongKeyRepository = new RaygunConfigRepository(
        db as any,
        generateEncryptionKey()
      );

      await expect(wrongKeyRepository.get(repoId)).rejects.toThrow(
        "Failed to decrypt Raygun configuration"
      );
    });
  });

  describe("update", () => {
    it("should update an existing configuration", async () => {
      const repoId = 123;
      const oldApplicationId = "550e8400-e29b-41d4-a716-446655440000";
      const newApplicationId = "660e8400-e29b-41d4-a716-446655440001";

      const created = await repository.create(repoId, oldApplicationId);
      
      // Wait a bit to ensure updated_at is different
      await new Promise((resolve) => setTimeout(resolve, 10));
      
      const updated = await repository.update(repoId, newApplicationId);

      expect(updated.repoId).toBe(String(repoId));
      expect(updated.applicationId).toBe(newApplicationId);
      expect(updated.id).toBe(created.id);
      expect(updated.createdAt).toEqual(created.createdAt);
      expect(updated.updatedAt.getTime()).toBeGreaterThan(created.updatedAt.getTime());
    });

    it("should throw error if configuration doesn't exist", async () => {
      const repoId = 999;
      const applicationId = "550e8400-e29b-41d4-a716-446655440000";

      await expect(repository.update(repoId, applicationId)).rejects.toThrow(
        "Raygun configuration not found"
      );
    });

    it("should replace the old application ID with the new one", async () => {
      const repoId = 123;
      const oldApplicationId = "550e8400-e29b-41d4-a716-446655440000";
      const newApplicationId = "660e8400-e29b-41d4-a716-446655440001";

      await repository.create(repoId, oldApplicationId);
      await repository.update(repoId, newApplicationId);

      const retrieved = await repository.get(repoId);
      expect(retrieved?.applicationId).toBe(newApplicationId);
    });
  });

  describe("delete", () => {
    it("should delete an existing configuration", async () => {
      const repoId = 123;
      const applicationId = "550e8400-e29b-41d4-a716-446655440000";

      await repository.create(repoId, applicationId);
      const deleted = await repository.delete(repoId);

      expect(deleted).toBe(true);

      const retrieved = await repository.get(repoId);
      expect(retrieved).toBeNull();
    });

    it("should return false if configuration doesn't exist", async () => {
      const deleted = await repository.delete(999);
      expect(deleted).toBe(false);
    });

    it("should remove the configuration from the database", async () => {
      const repoId = 123;
      const applicationId = "550e8400-e29b-41d4-a716-446655440000";

      await repository.create(repoId, applicationId);
      await repository.delete(repoId);

      const retrieved = await repository.get(repoId);
      expect(retrieved).toBeNull();
    });
  });

  describe("encryption round-trip", () => {
    it("should correctly encrypt and decrypt application IDs", async () => {
      const testCases = [
        "550e8400-e29b-41d4-a716-446655440000",
        "123e4567-e89b-12d3-a456-426614174000",
        "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      ];

      for (const applicationId of testCases) {
        const repoId = Math.floor(Math.random() * 10000);
        await repository.create(repoId, applicationId);
        const retrieved = await repository.get(repoId);
        expect(retrieved?.applicationId).toBe(applicationId);
      }
    });
  });

  describe("repository scoping", () => {
    it("should isolate configurations between repositories", async () => {
      const repo1Id = 123;
      const repo2Id = 456;
      const app1Id = "550e8400-e29b-41d4-a716-446655440000";
      const app2Id = "660e8400-e29b-41d4-a716-446655440001";

      await repository.create(repo1Id, app1Id);
      await repository.create(repo2Id, app2Id);

      const config1 = await repository.get(repo1Id);
      const config2 = await repository.get(repo2Id);

      expect(config1?.applicationId).toBe(app1Id);
      expect(config2?.applicationId).toBe(app2Id);
      expect(config1?.id).not.toBe(config2?.id);
    });

    it("should not affect other repositories when updating", async () => {
      const repo1Id = 123;
      const repo2Id = 456;
      const app1Id = "550e8400-e29b-41d4-a716-446655440000";
      const app2Id = "660e8400-e29b-41d4-a716-446655440001";
      const newApp1Id = "770e8400-e29b-41d4-a716-446655440002";

      await repository.create(repo1Id, app1Id);
      await repository.create(repo2Id, app2Id);
      await repository.update(repo1Id, newApp1Id);

      const config1 = await repository.get(repo1Id);
      const config2 = await repository.get(repo2Id);

      expect(config1?.applicationId).toBe(newApp1Id);
      expect(config2?.applicationId).toBe(app2Id);
    });

    it("should not affect other repositories when deleting", async () => {
      const repo1Id = 123;
      const repo2Id = 456;
      const app1Id = "550e8400-e29b-41d4-a716-446655440000";
      const app2Id = "660e8400-e29b-41d4-a716-446655440001";

      await repository.create(repo1Id, app1Id);
      await repository.create(repo2Id, app2Id);
      await repository.delete(repo1Id);

      const config1 = await repository.get(repo1Id);
      const config2 = await repository.get(repo2Id);

      expect(config1).toBeNull();
      expect(config2?.applicationId).toBe(app2Id);
    });
  });
});
