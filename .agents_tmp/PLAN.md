# 1. OBJECTIVE
Fix the Railway build failure caused by Prisma schema errors (`@field` attribute not recognized).

# 2. CONTEXT SUMMARY
- Project: central-alberta-markets (Next.js + Prisma)
- Error: Prisma doesn't recognize `@field(name: "...")` attributes in schema.prisma
- Root cause: `@field` is not a standard Prisma attribute - needs preview feature or removal
- Railway project "aware-success" failing on build

# 3. APPROACH OVERVIEW
Simple fix: Remove all `@field(name: "...")` attributes from Prisma schema. Let Prisma use default column names (typically camelCase or snake_case based on Prisma version).

# 4. IMPLEMENTATION STEPS

## Step 1: Find Schema File
- Run: `find ~/central-alberta-markets -name "schema.prisma"`
- Expected location: `prisma/schema.prisma`

## Step 2: Edit Schema - Remove @field Attributes
- Open schema.prisma in a text editor
- Find and remove ALL instances of `@field(name: "...")`
- Example changes:
  - `passwordHash String @field(name: "password_hash")` → `passwordHash String`
  - `isAdmin Boolean @default(false) @field(name: "is_admin")` → `isAdmin Boolean @default(false)`
- There are 28 errors total - remove all of them

## Step 3: Generate Prisma Client
- Run: `cd ~/central-alberta-markets && npx prisma generate`
- Should complete without errors

## Step 4: Push to GitHub
```bash
cd ~/central-alberta-markets
git add .
git commit -m "Fix Prisma schema - remove @field attributes"
git push origin main
```

# 5. TESTING AND VALIDATION
- Run `npx prisma generate` - should succeed with no errors
- Railway build deploys successfully
- App runs at Railway URL

# COMMANDS FOR LOCAL MACHINE:
```bash
cd ~/central-alberta-markets
find . -name "schema.prisma"  # locate schema file

# Edit schema.prisma to remove all @field(name: "...") patterns
# Then test:
npx prisma generate
# Push:
git add .
git commit -m "Fix Prisma schema"
git push origin main
```
