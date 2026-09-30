// build.rs

extern crate embed_resource;

fn main() {
  embed_resource::compile("..\\Resources\\Resource.rc");
}
