mihailov.s@infra1:~/miker_p2p/log$ crontab -l
GEM_HOME=/usr/local/rvm/gems/ruby-2.2.5
IRBRC=/usr/local/rvm/rubies/ruby-2.2.5/.irbrc
MY_RUBY_HOME=/usr/local/rvm/rubies/ruby-2.2.5
PATH=/usr/local/rvm/gems/ruby-2.2.5/bin:/usr/local/rvm/gems/ruby-2.2.5@global/bin:/usr/local/rvm/rubies/ruby-2.2.5/bin:/usr/local/rvm/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
rvm_ruby_string=ruby-2.2.5
GEM_PATH=/usr/local/rvm/gems/ruby-2.2.5:/usr/local/rvm/gems/ruby-2.2.5@global
rvm_delete_flag=0
RUBY_VERSION=ruby-2.2.5
*/5 * * * * cd /home/mihailov.s/miker_p2p;ruby peer_cleanup.cron.rb >> /home/mihailov.s/miker_p2p/log/cron.log 2>&1