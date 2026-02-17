import { RaygunConfigRepository } from "../db/raygun";
import { createLogger } from "../logger";
import type { RaygunConfig } from "@open-inspect/shared";

const log = createLogger("raygun-config-service");

/**
 * UUID v4 regex pattern for validating Raygun Application IDs.
 * Raygun Application IDs are expected to be in UUID format.
 */
const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Service layer for managing Raygun configurations.
 * 
 * Provides business logic and validation on top of the RaygunConfigRepository,
 * including Application ID format validation and error handling.
 */
export class RaygunConfigService {
  constructor(private readonly repository: RaygunConfigRepository) {}

  /**
   * Get Raygun configuration for a repository.
   * 
   * @param repoId - Repository ID
   * @returns Decrypted RaygunConfig or null if not found
   * @throws Error if decryption fails or database error occurs
   */
  async getConfig(repoId: number): Promise<RaygunConfig | null> {
    try {
      return await this.repository.get(repoId);
    } catch (e) {
      log.error("Failed to get Raygun configuration", {
        repo_id: repoId,
        error: e instanceof Error ? e.message : String(e),
      });
      throw e;
    }
  }

  /**
   * Create or update Raygun configuration for a repository.
   * 
   * If a configuration already exists for the repository, it will be updated.
   * Otherwise, a new configuration will be created.
   * 
   * @param repoId - Repository ID
   * @param applicationId - Raygun Application ID (must be valid UUID format)
   * @returns Created or updated RaygunConfig
   * @throws Error if Application ID format is invalid or database operation fails
   */
  async setConfig(repoId: number, applicationId: string): Promise<RaygunConfig> {
    // Validate Application ID format before attempting to save
    if (!this.validateApplicationId(applicationId)) {
      log.warn("Invalid Raygun Application ID format", {
        repo_id: repoId,
        application_id_length: applicationId.length,
      });
      throw new Error(
        "Invalid Application ID format. Expected UUID format (e.g., 12345678-1234-4123-8123-123456789abc)"
      );
    }

    try {
      // Check if configuration already exists
      const existing = await this.repository.get(repoId);

      if (existing) {
        log.info("Updating existing Raygun configuration", {
          repo_id: repoId,
          config_id: existing.id,
        });
        return await this.repository.update(repoId, applicationId);
      } else {
        log.info("Creating new Raygun configuration", {
          repo_id: repoId,
        });
        return await this.repository.create(repoId, applicationId);
      }
    } catch (e) {
      log.error("Failed to set Raygun configuration", {
        repo_id: repoId,
        error: e instanceof Error ? e.message : String(e),
      });
      throw e;
    }
  }

  /**
   * Delete Raygun configuration for a repository.
   * 
   * @param repoId - Repository ID
   * @returns void
   * @throws Error if database operation fails
   */
  async deleteConfig(repoId: number): Promise<void> {
    try {
      const deleted = await this.repository.delete(repoId);
      
      if (deleted) {
        log.info("Deleted Raygun configuration", {
          repo_id: repoId,
        });
      } else {
        log.debug("No Raygun configuration to delete", {
          repo_id: repoId,
        });
      }
    } catch (e) {
      log.error("Failed to delete Raygun configuration", {
        repo_id: repoId,
        error: e instanceof Error ? e.message : String(e),
      });
      throw e;
    }
  }

  /**
   * Validate that an Application ID matches the expected UUID format.
   * 
   * Raygun Application IDs are UUIDs (version 4). This method validates
   * that the provided string matches the UUID v4 format.
   * 
   * @param applicationId - Application ID to validate
   * @returns true if valid UUID format, false otherwise
   */
  validateApplicationId(applicationId: string): boolean {
    if (!applicationId || typeof applicationId !== "string") {
      return false;
    }

    return UUID_REGEX.test(applicationId.trim());
  }
}
