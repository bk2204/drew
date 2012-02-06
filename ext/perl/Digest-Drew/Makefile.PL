use 5.006000;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'Digest::Drew',
    VERSION_FROM      => 'lib/Digest/Drew.pm',
    PREREQ_PM         => {'Test'        =>  0, },
    ($] >= 5.005 ?
      (ABSTRACT_FROM  => 'lib/Digest/Drew.pm',
       AUTHOR         => 'brian m. carlson <sandals@crustytoothpaste.net>') : ()),
    LIBS              => ['-L../../.. -ldrew -ldrew-impl'],
    DEFINE            => '',
    INC               => '-I../../../include -I.',
    OBJECT            => '$(O_FILES)',
);
