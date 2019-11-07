# the 
SRCNAME=foo

echo ":: Hello! Welcome to the .rs -> .so convenience script"

echo ":: Making a skeleton crate for leveraging Cargo (the Rust package manager)"
mkdir __skellycrate
mkdir __skellycrate/src

echo ":: Populating the necessary metadata files"
TOML=$'[package]\nname = "temp"\nversion = "0.1.0"\nedition = "2018"\n\n[lib]\ncrate-type = ["cdylib"]\n\n[dependencies]\nmaplit = "1.0.1"\nreo_rs = { git = "https://github.com/sirkibsirkib/reo_rs" }\n'
echo "$TOML" > ./__skellycrate/Cargo.toml

echo ":: Copying your Rust source into the skeleton crate"
cp ./$SRCNAME.rs ./__skellycrate/src/lib.rs -f

echo ":: Moving into skeleton crate"
cd __skellycrate

echo ":: Building crate with Cargo"
cargo build --release

echo ":: Moving out again. copying out $SRCNAME.so"
cd ..
cp ./__skellycrate/target/release/libtemp.so "./$SRCNAME.so"

echo ":: Removing skeleton crate"
rm ./__skellycrate -rf

echo ":: Done! Your lib file is $SRCNAME.so"

# This is an example of how to link your .so into your C program
# gcc ./main.c ./foo.so -o main



