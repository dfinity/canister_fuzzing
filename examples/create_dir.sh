#!/bin/bash

# Check if project name argument is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <project_name>"
  exit 1
fi

# Set project name
PROJECT_NAME="$1"

# Create directory structure
mkdir -p "$PROJECT_NAME"/{corpus,crashes,input,src}

# Create files
touch "$PROJECT_NAME/Cargo.toml"
touch "$PROJECT_NAME/build.rs"
touch "$PROJECT_NAME/corpus/.gitignore"
touch "$PROJECT_NAME/src/${PROJECT_NAME}.rs"

echo "Project structure for '$PROJECT_NAME' created successfully."
