class User < ApplicationRecord
  rolify
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
  enum role: { 'user' => 'user', 'vip' => 'vip', 'moderator' => 'moderator', 'admin' => 'admin' }
end
