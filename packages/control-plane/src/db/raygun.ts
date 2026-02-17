import { encryptToken, decryptToken, generateId } from "../auth/crypto";
import { createLogger } from "../logger";
import type { RaygunConfig } from "@open-inspect/shared";

const log = createLogger("raygun-config");

/**
 * Database row structure for raygun_configs table
 */
export interface RaygunConfigRow {
  id: string;
  repo_id: number;
  application_id_encrypted: string;
  created_at: number;
  updated_at: number;
}

/**
 * Repository class for managing Raygun configurations in D1 database.
 * 
 * Handles CRUD operations for Raygun Application IDs with transparent
 * encryption/decryption using the same encryption mechanism as repository secrets.
 */
export class RaygunConfigRepository {
  constructor(
    private readonly db: D1Database,
    private readonly encryptionKey: string
  ) {}

  /**
   * Get Raygun configuration for a repository.
   * 
   * @param repoId - Repository ID
   * @returns Decrypted RaygunConfig or null if not found
   */
  async get(repoId: number): Promise<RaygunConfig | null> {
    const result = await this.db
      .prepare(
        "SELECT id, repo_id, application_id_encrypted, created_at, updated_at FROM raygun_configs WHERE repo_id = ?"
      )
      .bind(repoId)
      .first<RaygunConfigRow>();

    if (!result) {
      return null;
    }

    try {
      const applicationId = await decryptToken(
        result.application_id_encrypted,
        this.encryptionKey
      );

      return {
        id: result.id,
        repoId: String(result.repo_id),
        applicationId,
        createdAt: new Date(result.created_at),
        updatedAt: new Date(result.updated_at),
      };
    } catch (e) {
      log.error("Failed to decrypt Raygun Application ID", {
        repo_id: repoId,
        config_id: result.id,
        error: e instanceof Error ? e.message : String(e),
      });
      throw new Error("Failed to decrypt Raygun configuration");
    }
  }

  /**
   * Create a new Raygun configuration for a repository.
   * 
   * @param repoId - Repository ID
   * @param applicationId - Raygun Application ID (will be encrypted)
   * @returns Created RaygunConfig
   * @throws Error if configuration already exists for this repository
   */
  async create(repoId: number, applicationId: string): Promise<RaygunConfig> {
    const id = generateId();
    const now = Date.now();
    const encrypted = await encryptToken(applicationId, this.encryptionKey);

    try {
      await this.db
        .prepare(
          `INSERT INTO raygun_configs (id, repo_id, application_id_encrypted, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?)`
        )
        .bind(id, repoId, encrypted, now, now)
        .run();

      return {
        id,
        repoId: String(repoId),
        applicationId,
        createdAt: new Date(now),
        updatedAt: new Date(now),
      };
    } catch (e) {
      log.error("Failed to create Raygun configuration", {
        repo_id: repoId,
        error: e instanceof Error ? e.message : String(e),
      });
      throw new Error("Failed to create Raygun configuration");
    }
  }

  /**
   * Update an existing Raygun configuration for a repository.
   * 
   * @param repoId - Repository ID
   * @param applicationId - New Raygun Application ID (will be encrypted)
   * @returns Updated RaygunConfig
   * @throws Error if configuration doesn't exist
   */
  async update(repoId: number, applicationId: string): Promise<RaygunConfig> {
    const existing = await this.get(repoId);
    if (!existing) {
      throw new Error("Raygun configuration not found");
    }

    const now = Date.now();
    const encrypted = await encryptToken(applicationId, this.encryptionKey);

    try {
      await this.db
        .prepare(
          `UPDATE raygun_configs 
           SET application_id_encrypted = ?, updated_at = ?
           WHERE repo_id = ?`
        )
        .bind(encrypted, now, repoId)
        .run();

      return {
        id: existing.id,
        repoId: String(repoId),
        applicationId,
        createdAt: existing.createdAt,
        updatedAt: new Date(now),
      };
    } catch (e) {
      log.error("Failed to update Raygun configuration", {
        repo_id: repoId,
        error: e instanceof Error ? e.message : String(e),
      });
      throw new Error("Failed to update Raygun configuration");
    }
  }

  /**
   * Delete Raygun configuration for a repository.
   * 
   * @param repoId - Repository ID
   * @returns true if configuration was deleted, false if it didn't exist
   */
  async delete(repoId: number): Promise<boolean> {
    try {
      const result = await this.db
        .prepare("DELETE FROM raygun_configs WHERE repo_id = ?")
        .bind(repoId)
        .run();

      return (result.meta?.changes ?? 0) > 0;
    } catch (e) {
      log.error("Failed to delete Raygun configuration", {
        repo_id: repoId,
        error: e instanceof Error ? e.message : String(e),
      });
      throw new Error("Failed to delete Raygun configuration");
    }
  }
}
