# AWS Provider
provider "aws" {
   region = "ap-south-1"
   profile = "apeksh"
}

# Generate new private key 
resource "tls_private_key" "my_key" {
  algorithm = "RSA"
}

# Generate a key-pair with above key
resource "aws_key_pair" "deployer" {
  key_name   = "efs-key"
  public_key = tls_private_key.my_key.public_key_openssh
}

# Saving Key Pair for ssh login for Client if needed
resource "null_resource" "save_key_pair"  {
provisioner "local-exec" {
command = "echo  ${tls_private_key.my_key.private_key_pem} > mykey.pem"
  }
}

# Deafult VPC
resource "aws_default_vpc" "default" {
  tags = {
    Name = "Default VPC"
  }
}

# Creating a new security group for EC2 instance with ssh and http inbound rules
resource "aws_security_group" "ec2_security_group" {
  name        = "ec2_security_group"
  description = "Allow SSH and HTTP"
  vpc_id      = aws_default_vpc.default.id                      

  ingress {
    description = "SSH from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "EFS mount target"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

 ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


# EC2 instance 
resource "aws_instance" "web" {
  ami           = "ami-00b494a3f139ba61f"
  instance_type = "t2.micro"
  key_name = aws_key_pair.deployer.key_name
  security_groups = [aws_security_group.ec2_security_group.name]
  tags = {
     Name = "WEB"
  } 

 provisioner "local-exec" {
  command = "echo ${aws_instance.web.public_ip} > publicIP.txt"
 }
}

# Creating EFS file system
resource "aws_efs_file_system" "efs" {
  creation_token = "my-efs"

  tags = {
    Name = "MyProduct"
  }
}

resource "aws_efs_mount_target" "mount" {
  file_system_id = aws_efs_file_system.efs.id
  subnet_id      = aws_instance.web.subnet_id
  security_groups = [aws_security_group.ec2_security_group.id]

}

resource "null_resource" "configure_nfs" {
  depends_on = [aws_efs_mount_target.mount]
   connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.my_key.private_key_pem
    host     = aws_instance.web.public_ip
   }
  provisioner "remote-exec" {
    inline = [
      "sudo yum install httpd php git -y -q ",
      "sudo systemctl start httpd",
      "sudo systemctl enable httpd",
      # "sudo yum -y install nfs-utils",     # Amazon ami has pre installed nfs utils
      "sudo mount -t nfs -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport ${aws_efs_file_system.efs.dns_name}:/  /var/www/html",
      "echo ${aws_efs_file_system.efs.dns_name}:/ /var/www/html nfs4 defaults,_netdev 0 0  | sudo cat >> /etc/fstab " ,
      "sudo chmod go+rw /var/www/html",
      "sudo git clone https://github.com/Apeksh742/EC2_instance_with_terraform.git /var/www/html",
    ]
  }
}

# Creating New Origin Access Identity
resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "new-acess-identity"
}
 
# Creating new S3 bucket 
resource "aws_s3_bucket" "my_bucket" {

  bucket = "mybucket4efs.com"  #Enter unique name here
  acl    = "private"
  tags = {
    Name        = "My bucket"
  }
}

# Bucket Policy for allowing acess to cloudfront distribution
resource "aws_s3_bucket_policy" "my_bucket_policy" {
  bucket = aws_s3_bucket.my_bucket.id

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Id": "PolicyForCloudFrontPrivateContent",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity ${aws_cloudfront_origin_access_identity.origin_access_identity.id}"
            },
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::${aws_s3_bucket.my_bucket.bucket}/*"
        }
    ]
}
POLICY
}

# Storing Objects in S3 bucket 
resource "aws_s3_bucket_object" "object" {
  acl = "public-read"
  depends_on = [aws_s3_bucket.my_bucket]
  bucket = aws_s3_bucket.my_bucket.id
  key    = "WALLPAPER.jpg"
  source = "./images/WALLPAPER2.jpg"   # Provide exact path of your file
}

locals {
  s3_origin_id = "myS3Origin"
}

# Creating CloudFront Distribution 
resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.my_bucket.bucket_regional_domain_name
    origin_id   = local.s3_origin_id
  
s3_origin_config {
  origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
    }

  }
 
  enabled             = true
  is_ipv6_enabled     = true

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  # Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern     = "/content/immutable/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 1
  ordered_cache_behavior {
    path_pattern     = "/content/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  price_class = "PriceClass_All"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  tags = {
    Environment = "production"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

# Retrieve CloudFront Domain 
resource "null_resource" "CloudFront_Domain" {
  depends_on = [aws_cloudfront_distribution.s3_distribution]

  provisioner "local-exec" {
    command = "echo ${aws_cloudfront_distribution.s3_distribution.domain_name} > CloudFrontURL.txt" 
  }
}







