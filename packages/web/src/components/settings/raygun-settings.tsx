"use client";

import { useState } from "react";

interface RaygunSettingsProps {
  repoOwner: string;
  repoName: string;
  currentApplicationId?: string;
  onSave: (applicationId: string) => Promise<void>;
  onDelete: () => Promise<void>;
}

export function RaygunSettings({
  repoOwner,
  repoName,
  currentApplicationId,
  onSave,
  onDelete,
}: RaygunSettingsProps) {
  const [applicationId, setApplicationId] = useState(currentApplicationId || "");
  const [isSaving, setIsSaving] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSave = async () => {
    if (!applicationId.trim()) {
      setError("Application ID is required");
      return;
    }

    // Basic UUID format validation
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(applicationId.trim())) {
      setError("Invalid Application ID format. Expected UUID format (e.g., 12345678-1234-4123-8123-123456789abc)");
      return;
    }

    setError(null);
    setIsSaving(true);

    try {
      await onSave(applicationId.trim());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save configuration");
    } finally {
      setIsSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm("Are you sure you want to delete the Raygun configuration?")) {
      return;
    }

    setError(null);
    setIsDeleting(true);

    try {
      await onDelete();
      setApplicationId("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete configuration");
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-medium">Raygun Configuration</h3>
        <p className="text-sm text-gray-500 mt-1">
          Configure Raygun error monitoring for {repoOwner}/{repoName}
        </p>
      </div>

      <div className="space-y-3">
        <div>
          <label htmlFor="raygun-app-id" className="block text-sm font-medium text-gray-700 mb-1">
            Application ID
          </label>
          <input
            id="raygun-app-id"
            type="text"
            value={applicationId}
            onChange={(e) => {
              setApplicationId(e.target.value);
              setError(null);
            }}
            placeholder="12345678-1234-4123-8123-123456789abc"
            className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            disabled={isSaving || isDeleting}
          />
          <p className="text-xs text-gray-500 mt-1">
            Find your Application ID in Raygun under Application Settings
          </p>
        </div>

        {error && (
          <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-md p-3">
            {error}
          </div>
        )}

        <div className="flex gap-2">
          <button
            onClick={handleSave}
            disabled={isSaving || isDeleting || !applicationId.trim()}
            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
          >
            {isSaving ? "Saving..." : currentApplicationId ? "Update" : "Save"}
          </button>

          {currentApplicationId && (
            <button
              onClick={handleDelete}
              disabled={isSaving || isDeleting}
              className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
            >
              {isDeleting ? "Deleting..." : "Delete"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
