use ExtUtils::MakeMaker;
WriteMakefile(
	'NAME'			=> 'POE::Component::PXR',
	'VERSION_FROM'	=> 'POE/Component/PXR.pm',
	'PREREQ_PM'		=>	{
	
		'POE'				=> 0,
		'PXR'				=> 0,
		'POE::Filter::XML'	=> 0,
	}
);
