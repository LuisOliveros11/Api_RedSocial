/*
  Warnings:

  - You are about to drop the column `latitude` on the `post` table. All the data in the column will be lost.
  - You are about to drop the column `longitude` on the `post` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE `post` DROP COLUMN `latitude`,
    DROP COLUMN `longitude`,
    ADD COLUMN `city` VARCHAR(191) NULL,
    ADD COLUMN `country` VARCHAR(191) NULL;
