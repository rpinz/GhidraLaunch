// build.rs

extern crate embed_resource;

fn main() {
  _ = embed_resource::compile("..\\Resources\\Resource.rc");
}
