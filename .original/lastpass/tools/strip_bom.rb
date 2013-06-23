#!/usr/bin/env ruby

DRY_RUN = ARGV.delete("--dry-run") || ARGV.delete("-n")

Dir["../**/*"].each do |filename|
    if File.file? filename
        without_bom = nil
        File.open filename, "rb" do |io|
            bom = io.read 3
            if bom == "\xEF\xBB\xBF"
                without_bom = io.read
            elsif bom && bom[0] == "\xEF"
                puts "Looks like some other kind of BOM in #{filename}"
            end
        end

        if without_bom
            puts "Stripping BOM from #{filename}"
            unless DRY_RUN
                File.open filename, "wb" do |io|
                    io.write without_bom
                end
            end
        end
    end
end
